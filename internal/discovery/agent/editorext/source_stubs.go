package editorext

import "context"

// Stubs for editor sources not yet wired. Each returns empty so the
// multi-editor chain runs unconditionally.

// NewJetBrainsCollector returns a stub JetBrains-family collector.
//
// TODO(cdms-iter): walk the per-product config + plugins directories.
// Linux:   ~/.local/share/JetBrains/<ProductCode><Version>/plugins/
// macOS:   ~/Library/Application Support/JetBrains/<ProductCode><Version>/plugins/
// Windows: %APPDATA%\JetBrains\<ProductCode><Version>\plugins\
//
// ProductCode is "IntelliJIdea" / "PyCharm" / "GoLand" / etc. Each
// plugin is a directory containing META-INF/plugin.xml — parse it for
// <id>, <name>, <version>, <vendor>, <depends>, <idea-version>.
// Bundled (system-installed) plugins land in <product>/plugins/; user
// plugins land in ~/.local/share/JetBrains/.../plugins/.
func NewJetBrainsCollector() Collector { return sourceStub{name: "jetbrains-stub"} }

// NewSublimeCollector returns a stub Sublime Text collector.
//
// TODO(cdms-iter): walk ~/.config/sublime-text/Packages/ (Linux),
// ~/Library/Application Support/Sublime Text/Packages/ (macOS),
// %APPDATA%\Sublime Text\Packages\ (Windows). Each package is a
// directory; metadata lives in messages/install.txt or the .sublime-package
// archive (zip) when installed via Package Control.
func NewSublimeCollector() Collector { return sourceStub{name: "sublime-stub"} }

// NewVimCollector returns a stub Vim/Neovim collector.
//
// TODO(cdms-iter): plugin layout varies wildly by plugin manager.
// Cover the common ones:
//   - vim-plug:     ~/.vim/plugged/<name>/
//   - Vundle:       ~/.vim/bundle/<name>/
//   - pathogen:     ~/.vim/bundle/<name>/
//   - neovim:       ~/.local/share/nvim/site/pack/*/start/<name>/
//   - lazy.nvim:    ~/.local/share/nvim/lazy/<name>/
//   - packer.nvim:  ~/.local/share/nvim/site/pack/packer/start/<name>/
//
// Each is a clone of the upstream git repo; identity = directory name
// + (optionally) `git remote get-url origin` for the canonical source.
func NewVimCollector() Collector { return sourceStub{name: "vim-stub"} }

// NewEmacsCollector returns a stub Emacs collector.
//
// TODO(cdms-iter): walk ~/.emacs.d/elpa/<package>-<version>/ and parse
// the <package>-pkg.el file (Lisp; trivial to scan for the metadata
// fields: name, version, summary, requires).
func NewEmacsCollector() Collector { return sourceStub{name: "emacs-stub"} }

type sourceStub struct{ name string }

func (s sourceStub) Name() string { return s.name }
func (s sourceStub) Collect(_ context.Context) ([]Extension, error) {
	return []Extension{}, nil
}
