//go:build windows

package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"image"
	_ "image/png"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/lxn/walk"
	decl "github.com/lxn/walk/declarative"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

//go:embed static/logo.png
var logoBytes []byte

// runWizard launches the simplified GUI installer for Windows.
// It has a single window containing the Vulnertrack logo, a simple description,
// and "Install" and "Cancel" buttons.
//
// On the kite-collector-osquery bundle artifact the same window also installs
// the embedded osqueryd as the kite-osqueryd sibling service (RFC-0156 R1).
// This is the gap the RFC opens with: the double-click wizard was the one
// surface RFC-0059 built for non-technical users, and it was also the one
// surface that could never deliver osquery-backed FIM/YARA discovery.
func runWizard(args setupArgs) error {
	defaults := installer.DetectDefaults()
	opts := defaults.Options

	if args.InstallDir != "" {
		if err := installer.ValidateInstallDir(args.InstallDir); err != nil {
			return fmt.Errorf("/DIR: %w", err)
		}
		opts.BinaryDir = filepath.Clean(args.InstallDir)
	}

	// One structured, Administrators-only install log per run (Section 6.4).
	// The progress bar vanishes with the window, so this is the only durable
	// record of what the wizard actually did.
	log := installer.OpenInstallLog(opts, args.LogPath)
	defer func() { _ = log.Close() }()
	log.Info("wizard setup started",
		"code", installer.LogCodeInstallStarted,
		"variant", setupVariant(),
		"version", version)

	// R7 pre-flight, before a single byte is written.
	opts = resolveBundleInstallDir(opts, nil, log)

	bundled := installer.BundleAvailable()
	osqueryVersion := installer.BundledOsqueryVersion()

	introText := "This wizard will configure and run the Vulnertrack Kite " +
		"Collector agent on your machine."
	if bundled {
		introText += fmt.Sprintf(
			"\n\nIt also installs osquery %s as the %q service for "+
				"file-integrity and YARA discovery — no extra download.",
			osqueryVersion, installer.OsquerySvcName)
	}

	// Decode embedded logo image
	img, _, err := image.Decode(bytes.NewReader(logoBytes))
	if err != nil {
		return fmt.Errorf("decode logo: %w", err)
	}

	var (
		mw                     *walk.MainWindow
		progressBar            *walk.ProgressBar
		descLbl                *walk.Label
		statusLbl              *walk.Label
		installBtn             *walk.PushButton
		cancelBtn              *walk.PushButton
		launchPushBtn          *walk.PushButton
		logoBmp                *walk.Bitmap
		installed              bool
		installCancelContainer *walk.Composite
		launchContainer        *walk.Composite
	)

	// Create bitmap from decoded image
	logoBmp, err = walk.NewBitmapFromImageForDPI(img, 96)
	if err != nil {
		return fmt.Errorf("create logo bitmap: %w", err)
	}
	defer logoBmp.Dispose()

	onCancel := func() {
		choice := walk.MsgBox(mw,
			"Cancel Install?",
			"Are you sure you want to cancel the installer? No changes have been made yet.",
			walk.MsgBoxYesNo|walk.MsgBoxIconQuestion)
		if choice == walk.DlgCmdYes {
			mw.Close()
		}
	}

	showSuccessDialog := func() {
		var dlg *walk.Dialog
		var acceptBtn *walk.PushButton
		var rejectBtn *walk.PushButton

		_, _ = (decl.Dialog{
			AssignTo:      &dlg,
			Title:         "Installation Complete",
			MinSize:       decl.Size{Width: 380, Height: 180},
			Size:          decl.Size{Width: 400, Height: 200},
			DefaultButton: &acceptBtn,
			CancelButton:  &rejectBtn,
			Background:    decl.SolidColorBrush{Color: walk.RGB(255, 255, 255)},
			Layout:        decl.VBox{Margins: decl.Margins{Left: 25, Top: 25, Right: 25, Bottom: 20}},
			Children: []decl.Widget{
				decl.Label{
					Text:      "Installation Successful!",
					Font:      decl.Font{Family: "Segoe UI", PointSize: 12, Bold: true},
					TextColor: walk.RGB(33, 37, 41),
				},
				decl.VSpacer{Size: 10},
				decl.Label{
					Text:      "Vulnertrack Kite Collector has been successfully installed.\n\nPortal URL: http://127.0.0.1:9090/kite-login",
					Font:      decl.Font{Family: "Segoe UI", PointSize: 10},
					TextColor: walk.RGB(108, 117, 125),
				},
				decl.VSpacer{},
				decl.Composite{
					Background: decl.SolidColorBrush{Color: walk.RGB(255, 255, 255)},
					Layout:     decl.HBox{MarginsZero: true},
					Children: []decl.Widget{
						decl.HSpacer{},
						decl.PushButton{
							AssignTo: &acceptBtn,
							Text:     "Open Dashboard",
							MinSize:  decl.Size{Width: 120, Height: 28},
							OnClicked: func() {
								launchDashboard(opts.BinaryPath())
								dlg.Accept()
							},
						},
						decl.HSpacer{Size: 10},
						decl.PushButton{
							AssignTo: &rejectBtn,
							Text:     "Close",
							MinSize:  decl.Size{Width: 80, Height: 28},
							OnClicked: func() {
								dlg.Cancel()
							},
						},
					},
				},
			},
		}).Run(mw)
	}

	startInstall := func() {
		if installed {
			showSuccessDialog()
			mw.Close()
			return
		}

		installBtn.SetEnabled(false)
		cancelBtn.SetEnabled(false)

		progressBar.SetVisible(true)
		progressBar.SetValue(0)
		_ = statusLbl.SetText("Starting installation...")

		go func() {
			// The bundle variant writes a ~55 MB payload through per-file
			// on-disk checksum verification, on a host whose AV may scan every
			// byte of it. 60s is comfortable for the plain install and far too
			// tight for that.
			timeout := 60 * time.Second
			if bundled {
				timeout = setupTimeout
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			updateUI := func(progress int, msg string) {
				mw.Synchronize(func() {
					progressBar.SetValue(progress)
					_ = statusLbl.SetText(msg)
				})
			}

			updateUI(15, "Copying binary...")
			time.Sleep(300 * time.Millisecond)

			updateUI(40, "Creating certificate store...")
			time.Sleep(300 * time.Millisecond)

			if opts.UserMode {
				updateUI(65, "Configuring user-mode agent...")
			} else {
				updateUI(65, fmt.Sprintf("Registering service %q...", installer.SvcName))
			}
			time.Sleep(300 * time.Millisecond)

			if bundled && !opts.UserMode {
				updateUI(75, fmt.Sprintf(
					"Installing osquery %s and registering %q...",
					osqueryVersion, installer.OsquerySvcName))
			}

			err := newRealInstallerWithLog(log, nil).Install(ctx, opts)
			if err != nil {
				log.Error("wizard setup failed",
					"code", installer.LogCodeInstallFailed,
					"error", err.Error())
				updateUI(100, "Installation failed.")
				mw.Synchronize(func() {
					walk.MsgBox(mw,
						"Installation Failed",
						fmt.Sprintf("The installer encountered an error:\n\n%s\n\nPlease try running the installer as Administrator.", err.Error()),
						walk.MsgBoxIconError|walk.MsgBoxOK)

					installBtn.SetEnabled(true)
					cancelBtn.SetEnabled(true)
					_ = installBtn.SetText("Retry")
				})
				return
			}

			updateUI(85, "Verifying installation...")
			state := installer.Probe(opts)
			osq := installer.ProbeOsquery(opts)
			time.Sleep(300 * time.Millisecond)

			log.Info("wizard setup completed",
				"code", installer.LogCodeInstallCompleted,
				"binary", state.BinaryPath,
				"service_state", state.ServiceState,
				"osquery_service_state", osq.ServiceState,
				"osquery_version", osq.Version)

			updateUI(100, "Installation complete!")

			doneText := "Vulnertrack Kite Collector has been successfully installed."
			if bundled && !opts.UserMode {
				doneText += fmt.Sprintf(
					"\nosquery %s is registered as %q (%s).",
					osq.Version, installer.OsquerySvcName, osq.ServiceState)
			}

			mw.Synchronize(func() {
				installed = true
				progressBar.SetVisible(false)

				_ = descLbl.SetText(doneText)
				_ = statusLbl.SetText("Portal URL: http://127.0.0.1:9090/kite-login")
				statusLbl.SetTextColor(walk.RGB(33, 37, 41))

				installCancelContainer.SetVisible(false)
				launchContainer.SetVisible(true)
			})
		}()
	}

	// Build window with a modern simplified layout (centered card design)
	err = (decl.MainWindow{
		AssignTo:   &mw,
		Title:      "Vulnertrack Kite Collector Setup",
		MinSize:    decl.Size{Width: 440, Height: 380},
		MaxSize:    decl.Size{Width: 440, Height: 380},
		Size:       decl.Size{Width: 440, Height: 380},
		Background: decl.SolidColorBrush{Color: walk.RGB(255, 255, 255)},
		Layout:     decl.VBox{Margins: decl.Margins{Left: 30, Top: 30, Right: 30, Bottom: 30}, Spacing: 0},
		Children: []decl.Widget{
			// Centered Logo
			decl.Composite{
				Background: decl.SolidColorBrush{Color: walk.RGB(255, 255, 255)},
				Layout:     decl.HBox{MarginsZero: true},
				Children: []decl.Widget{
					decl.HSpacer{},
					decl.ImageView{
						Image:   logoBmp,
						Mode:    decl.ImageViewModeShrink,
						MinSize: decl.Size{Width: 80, Height: 80},
						MaxSize: decl.Size{Width: 80, Height: 80},
					},
					decl.HSpacer{},
				},
			},
			decl.VSpacer{Size: 15},
			// Centered Title
			decl.Label{
				Text:      "Vulnertrack Kite Collector",
				Font:      decl.Font{Family: "Segoe UI", PointSize: 14, Bold: true},
				TextColor: walk.RGB(33, 37, 41),
				Alignment: decl.AlignHCenterVCenter,
			},
			decl.VSpacer{Size: 10},
			// Centered Description
			decl.Label{
				AssignTo:  &descLbl,
				Text:      introText,
				Font:      decl.Font{Family: "Segoe UI", PointSize: 10},
				TextColor: walk.RGB(108, 117, 125),
				Alignment: decl.AlignHCenterVCenter,
			},
			decl.VSpacer{Size: 20},
			// Progress Bar
			decl.ProgressBar{
				AssignTo: &progressBar,
				MaxValue: 100,
				MinValue: 0,
				Visible:  false,
			},
			decl.VSpacer{Size: 5},
			// Status Label
			decl.Label{
				AssignTo:  &statusLbl,
				Text:      "Ready to install.",
				Font:      decl.Font{Family: "Segoe UI", PointSize: 9},
				TextColor: walk.RGB(140, 140, 140),
				Alignment: decl.AlignHCenterVCenter,
			},
			decl.VSpacer{Size: 20},
			// Install / Cancel Buttons Container
			decl.Composite{
				AssignTo:   &installCancelContainer,
				Background: decl.SolidColorBrush{Color: walk.RGB(255, 255, 255)},
				Layout:     decl.HBox{MarginsZero: true},
				Children: []decl.Widget{
					decl.HSpacer{},
					decl.PushButton{
						AssignTo:  &installBtn,
						Text:      "Install",
						MinSize:   decl.Size{Width: 110, Height: 30},
						OnClicked: startInstall,
					},
					decl.HSpacer{Size: 10},
					decl.PushButton{
						AssignTo:  &cancelBtn,
						Text:      "Cancel",
						MinSize:   decl.Size{Width: 110, Height: 30},
						OnClicked: onCancel,
					},
					decl.HSpacer{},
				},
			},
			// Launch Button Container
			decl.Composite{
				AssignTo:   &launchContainer,
				Visible:    false,
				Background: decl.SolidColorBrush{Color: walk.RGB(255, 255, 255)},
				Layout:     decl.HBox{MarginsZero: true},
				Children: []decl.Widget{
					decl.HSpacer{},
					decl.PushButton{
						AssignTo: &launchPushBtn,
						Text:     "Launch Portal",
						MinSize:  decl.Size{Width: 140, Height: 34},
						OnClicked: func() {
							launchDashboard(opts.BinaryPath())
							mw.Close()
						},
					},
					decl.HSpacer{},
				},
			},
		},
	}).Create()
	if err != nil {
		return fmt.Errorf("create wizard window: %w", err)
	}

	mw.Run()
	return nil
}

func launchDashboard(binaryPath string) {
	exe := binaryPath
	if _, err := exec.LookPath(exe); err != nil && runtime.GOOS == "windows" {
		exe = filepath.Clean(binaryPath)
	}
	cmd := exec.Command(exe, "dashboard")
	setHideWindow(cmd)
	_ = cmd.Start()
}
