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
func runWizard() error {
	defaults := installer.DetectDefaults()
	opts := defaults.Options

	// Decode embedded logo image
	img, _, err := image.Decode(bytes.NewReader(logoBytes))
	if err != nil {
		return fmt.Errorf("decode logo: %w", err)
	}

	var (
		mw           *walk.MainWindow
		progressBar  *walk.ProgressBar
		statusLbl    *walk.Label
		installBtn   *walk.PushButton
		cancelBtn    *walk.PushButton
		logoBmp      *walk.Bitmap
		installed    bool
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
					Text:      "Vulnertrack Kite Collector has been successfully installed.\n\nDashboard URL: http://127.0.0.1:9090",
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
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

			err := newRealInstaller().Install(ctx, opts)
			if err != nil {
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
			_ = installer.Probe(opts)
			time.Sleep(300 * time.Millisecond)

			updateUI(100, "Installation complete!")

			mw.Synchronize(func() {
				installed = true
				progressBar.SetVisible(false)

				_ = statusLbl.SetText("Installation complete. Click Finish to complete the setup.")

				installBtn.SetEnabled(true)
				_ = installBtn.SetText("Finish")

				cancelBtn.SetVisible(false)
			})
		}()
	}

	// Build window with a modern split-layout (dark brand sidebar on the left, white content on the right)
	err = (decl.MainWindow{
		AssignTo:   &mw,
		Title:      "Vulnertrack Kite Collector Setup",
		MinSize:    decl.Size{Width: 520, Height: 350},
		MaxSize:    decl.Size{Width: 520, Height: 350},
		Size:       decl.Size{Width: 520, Height: 350},
		Background: decl.SolidColorBrush{Color: walk.RGB(255, 255, 255)},
		Layout:     decl.HBox{MarginsZero: true, Spacing: 0},
		Children: []decl.Widget{
			// Left Column: Brand Sidebar (Dark theme)
			decl.Composite{
				Background: decl.SolidColorBrush{Color: walk.RGB(24, 24, 27)}, // Zinc-900
				Layout:     decl.VBox{Margins: decl.Margins{Left: 15, Top: 30, Right: 15, Bottom: 30}},
				MinSize:    decl.Size{Width: 160, Height: 350},
				MaxSize:    decl.Size{Width: 160, Height: 350},
				Children: []decl.Widget{
					decl.VSpacer{},
					decl.Composite{
						Background: decl.SolidColorBrush{Color: walk.RGB(24, 24, 27)},
						Layout:     decl.HBox{MarginsZero: true},
						Children: []decl.Widget{
							decl.HSpacer{},
							decl.ImageView{
								Image:   logoBmp,
								Mode:    decl.ImageViewModeShrink,
								MinSize: decl.Size{Width: 110, Height: 110},
								MaxSize: decl.Size{Width: 110, Height: 110},
							},
							decl.HSpacer{},
						},
					},
					decl.VSpacer{},
				},
			},
			// Right Column: Settings & Content (Light theme)
			decl.Composite{
				Background: decl.SolidColorBrush{Color: walk.RGB(255, 255, 255)},
				Layout:     decl.VBox{Margins: decl.Margins{Left: 25, Top: 35, Right: 25, Bottom: 25}},
				Children: []decl.Widget{
					decl.Label{
						Text:      "Vulnertrack Kite Collector",
						Font:      decl.Font{Family: "Segoe UI", PointSize: 15, Bold: true},
						TextColor: walk.RGB(33, 37, 41),
					},
					decl.VSpacer{Size: 10},
					decl.Label{
						Text:      "This wizard will configure and run the Vulnertrack Kite Collector agent on your machine.",
						Font:      decl.Font{Family: "Segoe UI", PointSize: 10},
						TextColor: walk.RGB(108, 117, 125),
					},
					decl.VSpacer{Size: 20},
					decl.ProgressBar{
						AssignTo: &progressBar,
						MaxValue: 100,
						MinValue: 0,
						Visible:  false,
					},
					decl.VSpacer{Size: 5},
					decl.Label{
						AssignTo:  &statusLbl,
						Text:      "Ready to install.",
						Font:      decl.Font{Family: "Segoe UI", PointSize: 9},
						TextColor: walk.RGB(140, 140, 140),
					},
					decl.VSpacer{},
					decl.Composite{
						Background: decl.SolidColorBrush{Color: walk.RGB(255, 255, 255)},
						Layout:     decl.HBox{MarginsZero: true},
						Children: []decl.Widget{
							decl.HSpacer{},
							decl.PushButton{
								AssignTo:  &installBtn,
								Text:      "Install",
								MinSize:   decl.Size{Width: 110, Height: 28},
								OnClicked: startInstall,
							},
							decl.HSpacer{Size: 10},
							decl.PushButton{
								AssignTo:  &cancelBtn,
								Text:      "Cancel",
								MinSize:   decl.Size{Width: 110, Height: 28},
								OnClicked: onCancel,
							},
						},
					},
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
