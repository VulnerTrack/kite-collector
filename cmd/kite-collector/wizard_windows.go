//go:build windows

package main

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lxn/walk"
	decl "github.com/lxn/walk/declarative"

	"github.com/vulnertrack/kite-collector/internal/installer"
)

// runWizard launches the GUI installer for Windows. The wizard is composed of
// five pages stacked in a single Composite; navigation toggles per-page
// visibility instead of rebuilding the widget tree, so back/forward is cheap
// and the embedded form values persist across page transitions.
//
// The install step itself runs in a goroutine and posts progress lines back
// to the UI via MainWindow.Synchronize — keeping the message loop responsive
// and avoiding the "(Not Responding)" Windows kernel marker that operators
// read as "the installer crashed."
//
// Build note: lxn/walk renders with the modern (XP+) Common Controls when an
// app manifest is embedded via a .syso resource. The app.manifest in this
// directory plus `go run github.com/akavel/rsrc@latest -manifest app.manifest
// -o rsrc_windows_amd64.syso` produces that resource. Without it the wizard
// still works but draws with Win95-era widgets.
func runWizard() error {
	m := newWizardModel()

	var (
		mw        *walk.MainWindow
		backBtn   *walk.PushButton
		nextBtn   *walk.PushButton
		cancelBtn *walk.PushButton
		statusLbl *walk.Label

		welcomePage, settingsPage, confirmPage, installingPage, finishPage *walk.Composite

		binaryDirEdit *walk.LineEdit
		certsDirEdit  *walk.LineEdit
		userModeChk   *walk.CheckBox
		privNote      *walk.Label

		confirmText *walk.TextEdit

		progressEdit *walk.TextEdit
		progressBar  *walk.ProgressBar

		finishHeader *walk.Label
		finishBody   *walk.TextEdit
		openDashChk  *walk.CheckBox
	)

	const (
		pageWelcome = iota
		pageSettings
		pageConfirm
		pageInstalling
		pageFinish
	)
	current := pageWelcome

	// showPage is the single source of truth for page transitions. It updates
	// per-page visibility, the bottom button row, and the step counter label
	// so any new page added later only needs to register its composite.
	showPage := func(idx int) {
		pages := []*walk.Composite{welcomePage, settingsPage, confirmPage, installingPage, finishPage}
		for i, p := range pages {
			if p != nil {
				p.SetVisible(i == idx)
			}
		}
		current = idx

		// Buttons: Back hidden on first/installing/finish; Next becomes
		// "Install" before the install step and "Finish" after; Cancel
		// becomes "Close" on the finish page so the verbiage matches the
		// completed-state of the wizard.
		backVisible := idx == pageSettings || idx == pageConfirm
		backBtn.SetVisible(backVisible)

		switch idx {
		case pageWelcome:
			_ = nextBtn.SetText("Next >")
			nextBtn.SetEnabled(true)
		case pageSettings:
			_ = nextBtn.SetText("Next >")
			nextBtn.SetEnabled(true)
		case pageConfirm:
			_ = nextBtn.SetText("Install")
			nextBtn.SetEnabled(true)
		case pageInstalling:
			_ = nextBtn.SetText("Install")
			nextBtn.SetEnabled(false)
			cancelBtn.SetEnabled(false)
		case pageFinish:
			_ = nextBtn.SetText("Finish")
			nextBtn.SetEnabled(true)
			cancelBtn.SetVisible(false)
		}

		labels := []string{
			"Step 1 of 4 — Welcome",
			"Step 2 of 4 — Settings",
			"Step 3 of 4 — Confirm",
			"Step 4 of 4 — Installing…",
			"Done",
		}
		_ = statusLbl.SetText(labels[idx])
	}

	// readSettings copies the Settings-page widgets into the wizard model so
	// downstream pages and the install goroutine see the operator's edits.
	readSettings := func() {
		m.opts.BinaryDir = strings.TrimSpace(binaryDirEdit.Text())
		m.opts.CertsDir = strings.TrimSpace(certsDirEdit.Text())
		m.opts.UserMode = userModeChk.Checked()
		// Preserve the endpoint from defaults (the wizard doesn't expose it as
		// a field — enrollment happens later from the dashboard).
		if m.opts.BinaryDir == "" {
			m.opts.BinaryDir = installer.DefaultBinaryDir(m.opts.UserMode)
		}
		if m.opts.CertsDir == "" {
			m.opts.CertsDir = installer.DefaultCertsDir(m.opts.UserMode)
		}
	}

	// renderConfirm fills the read-only review text on the Confirm page so
	// operators see exactly what the install button will do. The summary uses
	// the same shape as the dashboard's install-preview card so they read
	// the same on both surfaces.
	renderConfirm := func() {
		readSettings()
		serviceStep := fmt.Sprintf("  3. Register the Windows service \"%s\"\r\n     (runs as %s)\r\n\r\n",
			installer.SvcDisplayName,
			modeLabel(m.opts.UserMode),
		)
		if m.opts.UserMode {
			serviceStep = "  3. Leave service registration for later\r\n     (requires Administrator privileges on Windows)\r\n\r\n"
		}
		s := fmt.Sprintf(
			"The wizard will:\r\n\r\n"+
				"  1. Copy this binary to:\r\n     %s\r\n\r\n"+
				"  2. Create the certificate store at:\r\n     %s\r\n\r\n"+
				"%s"+
				"After install you can finish onboarding (enroll, run probes,\r\n"+
				"start streaming) from the dashboard.",
			m.opts.BinaryPath(),
			m.opts.CertsDir,
			serviceStep,
		)
		_ = confirmText.SetText(s)
	}

	// appendProgress writes one line to the Installing-page progress log.
	// Called from the install goroutine via Synchronize so the TextEdit
	// mutation happens on the UI thread.
	appendProgress := func(line string) {
		mw.Synchronize(func() {
			cur := progressEdit.Text()
			if cur != "" {
				cur += "\r\n"
			}
			_ = progressEdit.SetText(cur + line)
		})
	}

	// finishWith renders the Finish page based on the post-install probe
	// result. Called once the install goroutine has fully completed.
	finishWith := func(probeState installer.State, installErr error) {
		mw.Synchronize(func() {
			if installErr != nil {
				_ = finishHeader.SetText("Install failed")
				_ = finishBody.SetText(formatFinishError(installErr, m.opts))
				openDashChk.SetChecked(false)
				openDashChk.SetVisible(false)
			} else {
				_ = finishHeader.SetText("Kite Collector is installed")
				_ = finishBody.SetText(formatFinishSuccess(probeState))
				openDashChk.SetVisible(true)
			}
			progressBar.SetValue(100)
			showPage(pageFinish)
		})
	}

	// startInstall kicks off the install goroutine. The UI is moved to the
	// Installing page first, then a goroutine runs realInstaller.Install
	// and Synchronizes progress + finish updates back to the UI.
	startInstall := func() {
		readSettings()
		_ = progressEdit.SetText("")
		progressBar.SetValue(0)
		showPage(pageInstalling)

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			appendProgress("Copying binary → " + m.opts.BinaryPath())
			mw.Synchronize(func() { progressBar.SetValue(20) })

			appendProgress("Creating certificate store → " + m.opts.CertsDir)
			mw.Synchronize(func() { progressBar.SetValue(40) })

			if m.opts.UserMode {
				appendProgress("Skipping service registration (Administrator required on Windows)")
			} else {
				appendProgress(fmt.Sprintf("Registering service %q", installer.SvcName))
			}
			mw.Synchronize(func() { progressBar.SetValue(70) })

			err := newRealInstaller().Install(ctx, m.opts)
			if err != nil {
				appendProgress("ERROR: " + err.Error())
			} else {
				appendProgress("Install complete.")
			}
			st := installer.Probe(m.opts)
			finishWith(st, err)
		}()
	}

	// onNext is the central dispatcher for the bottom-right primary button.
	// Each branch is small enough to stay inline; pushing it into a helper
	// would obscure the page-machine logic that lives in one place by design.
	onNext := func() {
		switch current {
		case pageWelcome:
			showPage(pageSettings)
		case pageSettings:
			readSettings()
			renderConfirm()
			showPage(pageConfirm)
		case pageConfirm:
			startInstall()
		case pageFinish:
			if openDashChk.Visible() && openDashChk.Checked() {
				launchDashboard(m.opts.BinaryPath())
			}
			mw.Close()
		}
	}

	onBack := func() {
		switch current {
		case pageSettings:
			showPage(pageWelcome)
		case pageConfirm:
			showPage(pageSettings)
		}
	}

	// onCancel asks for confirmation when the operator is mid-flow but not
	// mid-install. The Installing page disables Cancel entirely (best-effort
	// rollback during an MSI-style install is out of scope for this wizard).
	onCancel := func() {
		if current == pageInstalling {
			return
		}
		choice := walk.MsgBox(mw,
			"Cancel install?",
			"Cancel the kite-collector installer? No changes have been made yet.",
			walk.MsgBoxYesNo|walk.MsgBoxIconQuestion)
		if choice == walk.DlgCmdYes {
			mw.Close()
		}
	}

	// Build the window with the declarative API. Pages are siblings inside
	// the content composite — visibility is the navigation primitive.
	err := (decl.MainWindow{
		AssignTo: &mw,
		Title:    "Kite Collector Setup",
		MinSize:  decl.Size{Width: 560, Height: 420},
		Size:     decl.Size{Width: 600, Height: 460},
		Layout:   decl.VBox{MarginsZero: true},
		Children: []decl.Widget{
			decl.Composite{
				Layout: decl.VBox{Margins: decl.Margins{Left: 20, Top: 20, Right: 20, Bottom: 10}},
				Children: []decl.Widget{
					decl.Label{
						AssignTo: &statusLbl,
						Text:     "Step 1 of 4 — Welcome",
						Font:     decl.Font{Bold: true},
					},
				},
			},

			// All five pages live inside a single content composite. Only one
			// is Visible at a time; the others draw at zero height because
			// the parent VBox skips invisible children.
			decl.Composite{
				Layout: decl.VBox{Margins: decl.Margins{Left: 20, Top: 0, Right: 20, Bottom: 0}},
				Children: []decl.Widget{
					decl.Composite{
						AssignTo: &welcomePage,
						Layout:   decl.VBox{},
						Children: []decl.Widget{
							decl.Label{Text: "Welcome to Kite Collector Setup", Font: decl.Font{PointSize: 14, Bold: true}},
							decl.VSpacer{Size: 8},
							decl.Label{
								Text: "This wizard installs Kite Collector for the current Windows user.\n\n" +
									"You can review and edit the install paths on the next page. The wizard\n" +
									"will copy this binary into your user profile, create a data folder, and\n" +
									"leave service registration for an Administrator flow if needed.\n\n" +
									"Click Next to continue.",
							},
							decl.VSpacer{},
						},
					},

					decl.Composite{
						AssignTo: &settingsPage,
						Visible:  false,
						Layout:   decl.Grid{Columns: 3, Margins: decl.Margins{Top: 8}},
						Children: []decl.Widget{
							decl.Label{Text: "Install location:"},
							decl.LineEdit{
								AssignTo: &binaryDirEdit,
								Text:     m.opts.BinaryDir,
							},
							decl.PushButton{
								Text:    "Browse…",
								MinSize: decl.Size{Width: 90},
								OnClicked: func() {
									if p, ok := pickFolder(mw, "Choose install folder", binaryDirEdit.Text()); ok {
										_ = binaryDirEdit.SetText(p)
									}
								},
							},

							decl.Label{Text: "Certs / data folder:"},
							decl.LineEdit{
								AssignTo: &certsDirEdit,
								Text:     m.opts.CertsDir,
							},
							decl.PushButton{
								Text:    "Browse…",
								MinSize: decl.Size{Width: 90},
								OnClicked: func() {
									if p, ok := pickFolder(mw, "Choose certs / data folder", certsDirEdit.Text()); ok {
										_ = certsDirEdit.SetText(p)
									}
								},
							},

							decl.Label{Text: "Install for:"},
							decl.CheckBox{
								AssignTo: &userModeChk,
								Text:     "this user only (no Administrator privileges required)",
								Checked:  m.opts.UserMode,
								OnCheckedChanged: func() {
									// Swap path defaults when the operator
									// toggles the mode, so the LineEdits
									// reflect the canonical install location
									// for the newly-chosen scope.
									userMode := userModeChk.Checked()
									_ = binaryDirEdit.SetText(installer.DefaultBinaryDir(userMode))
									_ = certsDirEdit.SetText(installer.DefaultCertsDir(userMode))
									if privNote != nil {
										_ = privNote.SetText(privilegeHint(m.defaults.Detected.Privileged, userMode))
									}
								},
							},
							decl.HSpacer{},

							decl.HSpacer{},
							decl.Label{
								AssignTo:  &privNote,
								Text:      privilegeHint(m.defaults.Detected.Privileged, m.opts.UserMode),
								TextColor: walk.RGB(120, 120, 120),
							},
							decl.HSpacer{},
						},
					},

					decl.Composite{
						AssignTo: &confirmPage,
						Visible:  false,
						Layout:   decl.VBox{},
						Children: []decl.Widget{
							decl.Label{Text: "Review", Font: decl.Font{Bold: true}},
							decl.VSpacer{Size: 4},
							decl.TextEdit{
								AssignTo: &confirmText,
								ReadOnly: true,
								VScroll:  true,
							},
						},
					},

					decl.Composite{
						AssignTo: &installingPage,
						Visible:  false,
						Layout:   decl.VBox{},
						Children: []decl.Widget{
							decl.Label{Text: "Installing", Font: decl.Font{Bold: true}},
							decl.VSpacer{Size: 4},
							decl.ProgressBar{
								AssignTo: &progressBar,
								MaxValue: 100,
								MinValue: 0,
							},
							decl.VSpacer{Size: 8},
							decl.TextEdit{
								AssignTo: &progressEdit,
								ReadOnly: true,
								VScroll:  true,
							},
						},
					},

					decl.Composite{
						AssignTo: &finishPage,
						Visible:  false,
						Layout:   decl.VBox{},
						Children: []decl.Widget{
							decl.Label{
								AssignTo: &finishHeader,
								Text:     "Kite Collector is installed",
								Font:     decl.Font{PointSize: 12, Bold: true},
							},
							decl.VSpacer{Size: 4},
							decl.TextEdit{
								AssignTo: &finishBody,
								ReadOnly: true,
								VScroll:  true,
							},
							decl.VSpacer{Size: 8},
							decl.CheckBox{
								AssignTo: &openDashChk,
								Text:     "Open the Kite Collector dashboard now to enroll and verify",
								Checked:  true,
							},
						},
					},
				},
			},

			// Bottom button row. Layout pushed to the right so the primary
			// (Next / Install / Finish) action sits where Windows operators
			// expect — matching the convention every Setup.exe ships with.
			decl.Composite{
				Layout: decl.HBox{Margins: decl.Margins{Left: 20, Top: 8, Right: 20, Bottom: 12}},
				Children: []decl.Widget{
					decl.HSpacer{},
					decl.PushButton{
						AssignTo:  &backBtn,
						Text:      "< Back",
						MinSize:   decl.Size{Width: 100},
						OnClicked: onBack,
					},
					decl.PushButton{
						AssignTo:  &nextBtn,
						Text:      "Next >",
						MinSize:   decl.Size{Width: 100},
						OnClicked: onNext,
					},
					decl.PushButton{
						AssignTo:  &cancelBtn,
						Text:      "Cancel",
						MinSize:   decl.Size{Width: 100},
						OnClicked: onCancel,
					},
				},
			},
		},
	}).Create()
	if err != nil {
		return fmt.Errorf("create wizard window: %w", err)
	}

	// Initial page state must be set after Create() so the AssignTo'd
	// widget pointers are non-nil.
	showPage(pageWelcome)

	mw.Run()
	return nil
}

// wizardModel collects the state the wizard mutates across pages: the smart
// defaults probed at startup, the operator's edits on the Settings page, and
// the post-install probe result driving the Finish page. Kept tiny and
// pointer-free so it can be assigned by value in showPage closures.
type wizardModel struct {
	defaults installer.Defaults
	opts     installer.Options
}

func newWizardModel() *wizardModel {
	d := installer.DetectDefaults()
	// Double-click setup should work for a standard Windows user without UAC.
	// Keep system installs available from the Settings page, but make the
	// first-run path per-user so it does not write to Program Files.
	d.Options.UserMode = true
	d.Options.BinaryDir = installer.DefaultBinaryDir(true)
	d.Options.CertsDir = installer.DefaultCertsDir(true)
	return &wizardModel{
		defaults: d,
		opts:     d.Options,
	}
}

// modeLabel renders the "runs as" copy for the Confirm page. Mirrors the
// dashboard's mode chip so operators see the same vocabulary on both surfaces.
func modeLabel(userMode bool) string {
	if userMode {
		return "current user — no Administrator required"
	}
	return "LocalSystem — Administrator privileges required"
}

// privilegeHint returns the muted-grey caption under the install-mode
// checkbox. The text is adapt to the detected privilege state so a
// non-elevated double-click warns the operator before they hit the install
// error, instead of after.
func privilegeHint(privileged, userMode bool) string {
	switch {
	case userMode:
		return "User-mode install writes under your profile and does not need elevation."
	case privileged:
		return "Running with Administrator privileges — system install will succeed."
	default:
		return "Not elevated — system install will fail. Re-launch as Administrator, or check the box above."
	}
}

// formatFinishSuccess renders the post-install summary table. The bullet
// list intentionally mirrors what the CLI's printPostInstall function
// prints, so an operator who installed via the wizard and later checks
// status from the CLI sees a consistent vocabulary.
func formatFinishSuccess(st installer.State) string {
	check := func(ok bool) string {
		if ok {
			return "OK"
		}
		return "—"
	}
	var b strings.Builder
	b.WriteString("Install complete.\r\n\r\n")
	b.WriteString(fmt.Sprintf("  [%s] binary       %s\r\n", check(st.BinaryPresent), st.BinaryPath))
	b.WriteString(fmt.Sprintf("  [%s] certs dir    %s\r\n", check(st.CertsDirExists), st.CertsDir))
	b.WriteString(fmt.Sprintf("  [%s] enrolled     %s\r\n", check(st.CertsEnrolled), enrollmentBlurb(st)))
	b.WriteString(fmt.Sprintf("  [-]  service     %s\r\n\r\n", st.ServiceState))
	b.WriteString("Next: open the dashboard to enroll your platform token,\r\n")
	b.WriteString("run the six connection probes, and start streaming.")
	return b.String()
}

// formatFinishError renders the install-failure variant of the Finish page.
// The body cites the actual error string plus a copy-pasteable remediation
// command (re-run as Administrator OR run the equivalent CLI invocation),
// so the operator never leaves the wizard without a next step.
func formatFinishError(err error, opts installer.Options) string {
	errText := err.Error()
	var b strings.Builder
	b.WriteString("The install did not complete.\r\n\r\n")
	b.WriteString("Error: ")
	b.WriteString(errText)
	b.WriteString("\r\n\r\nWhat to try next:\r\n\r\n")
	if strings.Contains(strings.ToLower(errText), "already exists") {
		b.WriteString("  1. Remove the previous kite-collector service, then run setup again:\r\n\r\n")
		b.WriteString("     kite-collector.exe uninstall --user\r\n")
		b.WriteString("     sc.exe stop kite-collector\r\n")
		b.WriteString("     sc.exe delete kite-collector\r\n\r\n")
		b.WriteString("  2. If sc.exe reports access denied, open PowerShell as Administrator\r\n")
		b.WriteString("     and run the same sc.exe commands there.\r\n\r\n")
		b.WriteString("  3. Then run setup again, or run:\r\n\r\n")
		b.WriteString("     ")
		b.WriteString(equivalentCLI(opts))
		return b.String()
	}
	b.WriteString("  1. If the error mentions \"access denied\", close this wizard,\r\n")
	b.WriteString("     right-click kite-collector.exe and choose \"Run as administrator\",\r\n")
	b.WriteString("     then re-run the wizard.\r\n\r\n")
	b.WriteString("  2. Or install in user mode (no Administrator required) — go back\r\n")
	b.WriteString("     to Settings and check \"this user only\".\r\n\r\n")
	b.WriteString("  3. Or run the equivalent command from a terminal:\r\n\r\n")
	b.WriteString("     ")
	b.WriteString(equivalentCLI(opts))
	return b.String()
}

// enrollmentBlurb returns the per-row caption for the "enrolled" line on the
// Finish summary. Kept distinct from the CLI's enrollmentLabel because the
// wizard's body is sentence-cased, whereas the CLI uses fragments.
func enrollmentBlurb(st installer.State) string {
	switch {
	case st.CertsEnrolled:
		return "ca.pem + agent.pem + agent-key.pem present"
	case st.CertsDirExists:
		return "not yet — enroll from the dashboard"
	default:
		return "certs dir missing"
	}
}

// equivalentCLI renders the kite-collector install command that matches the
// wizard's collected options. Surfaced on the failure-finish page so a stuck
// operator can paste it into an elevated terminal and try again.
func equivalentCLI(opts installer.Options) string {
	parts := []string{"kite-collector.exe", "install"}
	if opts.UserMode {
		parts = append(parts, "--user")
	}
	if opts.BinaryDir != "" {
		parts = append(parts, "--binary-dir", quoteIfNeeded(opts.BinaryDir))
	}
	if opts.CertsDir != "" {
		parts = append(parts, "--certs-dir", quoteIfNeeded(opts.CertsDir))
	}
	return strings.Join(parts, " ")
}

func quoteIfNeeded(v string) string {
	if strings.ContainsAny(v, " \t") {
		return `"` + v + `"`
	}
	return v
}

// pickFolder opens the standard Windows folder-picker dialog seeded with the
// current LineEdit value. Returns the chosen path and true, or empty + false
// when the operator cancels.
func pickFolder(parent walk.Form, title, seed string) (string, bool) {
	dlg := &walk.FileDialog{
		Title:    title,
		FilePath: seed,
	}
	ok, err := dlg.ShowBrowseFolder(parent)
	if err != nil || !ok {
		return "", false
	}
	return dlg.FilePath, true
}

// launchDashboard fires off `kite-collector dashboard` as a detached process
// so the wizard window can close immediately and the operator sees the
// dashboard's banner come up in a fresh terminal. The browser auto-open
// inside the dashboard subcommand handles the rest.
//
// We spawn the freshly-installed binary at binaryPath rather than os.Args[0]:
// the wizard binary may live in the user's Downloads folder (the source the
// install copied from), and after Finish the operator should be running the
// installed copy.
func launchDashboard(binaryPath string) {
	exe := binaryPath
	if _, err := exec.LookPath(exe); err != nil && runtime.GOOS == "windows" {
		// Fall back to the absolute path Win32 cmd.exe accepts even when
		// the directory is not on PATH.
		exe = filepath.Clean(binaryPath)
	}
	cmd := exec.Command(exe, "dashboard")
	// Detach: don't inherit stdin/stdout/stderr, and don't WAIT on Start().
	_ = cmd.Start()
}
