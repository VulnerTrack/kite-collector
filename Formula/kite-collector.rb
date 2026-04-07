# Homebrew formula for kite-collector
# Install: brew install vulnertrack/tap/kite-collector
class KiteCollector < Formula
  desc "Cybersecurity asset discovery, configuration audit, and posture analysis agent"
  homepage "https://github.com/VulnerTrack/kite-collector"
  version "0.2.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/VulnerTrack/kite-collector/releases/download/v#{version}/kite-collector_darwin_arm64"
      sha256 "PLACEHOLDER_SHA256_DARWIN_ARM64"
    end

    on_intel do
      url "https://github.com/VulnerTrack/kite-collector/releases/download/v#{version}/kite-collector_darwin_amd64"
      sha256 "PLACEHOLDER_SHA256_DARWIN_AMD64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/VulnerTrack/kite-collector/releases/download/v#{version}/kite-collector_linux_arm64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    end

    on_intel do
      url "https://github.com/VulnerTrack/kite-collector/releases/download/v#{version}/kite-collector_linux_amd64"
      sha256 "PLACEHOLDER_SHA256_LINUX_AMD64"
    end
  end

  def install
    cpu = Hardware::CPU.arm? ? "arm64" : "amd64"
    os = OS.mac? ? "darwin" : "linux"
    bin.install "kite-collector_#{os}_#{cpu}" => "kite-collector"
  end

  test do
    assert_match "kite-collector", shell_output("#{bin}/kite-collector version")
  end
end
