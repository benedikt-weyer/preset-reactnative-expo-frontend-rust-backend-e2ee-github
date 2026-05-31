{
  description = "Flutter development environment for musestruct";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
            android_sdk.accept_license = true;
          };

        };

        buildToolsVersion = "36.0.0";
        additionalBuildToolsVersion = "35.0.0";
        cmakeVersion = "3.22.1";
        
        androidComposition = pkgs.androidenv.composeAndroidPackages {
          buildToolsVersions = [ buildToolsVersion additionalBuildToolsVersion ];
          platformVersions = [ "36" "35" "34"];
          abiVersions = [ "armeabi-v7a" "arm64-v8a" "x86_64" ];
          systemImageTypes = [ "google_apis" "google_apis_playstore" ];
          includeEmulator = true;
          useGoogleAPIs = true;
          includeNDK = true;
          ndkVersions = [ "27.1.12297006" ];
          includeSystemImages = true;
          includeCmake = true;
          cmakeVersions = [ cmakeVersion ];
        };
        androidSdk = androidComposition.androidsdk;

      in
      {
        devShells.default = pkgs.mkShell rec {
          buildInputs = with pkgs; [

            # Android development
            androidSdk
            jdk17

            # React Native development
            nodejs_24
            pnpm
            eas-cli
            gtk3
            
            # Rust development
            rustc
            cargo
            cargo-watch
            rustfmt
            clippy
            rust-analyzer
          ];

          # Set environment variables for the shell
          ANDROID_HOME = "${androidSdk}/libexec/android-sdk";
          ANDROID_SDK_ROOT = "${androidSdk}/libexec/android-sdk";
          JAVA_HOME = "${pkgs.jdk17}";
          CHROME_EXECUTABLE = "${pkgs.google-chrome}/bin/google-chrome-stable";
          ANDROID_NDK_ROOT="$ANDROID_HOME/ndk-bundle";
          GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${ANDROID_HOME}/build-tools/${buildToolsVersion}/aapt2";

          shellHook = ''
            # Set up Android SDK
            export ANDROID_HOME="${androidSdk}/libexec/android-sdk"
            export ANDROID_SDK_ROOT="$ANDROID_HOME"
            export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

            export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk-bundle";
            export GRADLE_OPTS="-Dorg.gradle.project.android.aapt2FromMavenOverride=${ANDROID_HOME}/build-tools/${buildToolsVersion}/aapt2"

            export PKG_CONFIG_PATH="${pkgs.gtk3}/lib/pkgconfig:${pkgs.glib}/lib/pkgconfig:${pkgs.sysprof}/lib/pkgconfig:${pkgs.libsecret}/lib/pkgconfig:${pkgs.libsoup_3}/lib/pkgconfig:${pkgs.gst_all_1.gstreamer}/lib/pkgconfig:${pkgs.gst_all_1.gst-plugins-base}/lib/pkgconfig:${pkgs.pulseaudio}/lib/pkgconfig:${pkgs.alsa-lib}/lib/pkgconfig:$PKG_CONFIG_PATH"
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [
              pkgs.gtk3
            ]}:$LD_LIBRARY_PATH"

            
            # Set up Java
            export JAVA_HOME="${pkgs.jdk17}"
            
            # Chrome for web development
            export CHROME_EXECUTABLE="${pkgs.google-chrome}/bin/google-chrome-stable"
            
            # Rust development aliases
            alias start-backend="./scripts/start-backend.sh"
            alias stop-backend="./scripts/stop-backend.sh"
            
            # Android emulator aliases
            alias start-emulator="./scripts/start-emulator.sh"
            alias start-emulator-software="./scripts/start-emulator-software.sh"
            alias start-emulator-headless="./scripts/start-emulator-headless.sh"
            alias list-emulators="./scripts/list-emulators.sh"
            alias create-emulator="./scripts/create-emulator.sh"
            alias delete-emulator="./scripts/delete-emulator.sh"
            
            echo "🚀 Flutter development environment activated!"
            echo ""
            echo "Available tools:"
            echo "  - Rust: $(rustc --version)"
            echo "  - Cargo: $(cargo --version)"
            echo "  - Android SDK: $ANDROID_HOME"
            echo "  - Java: $(java -version 2>&1 | head -n1)"
            echo "  - Repo help: run 'help' to list project commands"
            echo ""
            echo "Getting started:"
            echo ""
            echo "  Rust:"
            echo "    1. Run 'cargo new project_name' to create a new Rust project"
            echo "    2. Run 'start-backend' for hot-reload development in apps/backend/ dir"
            echo "    3. Run 'cargo build' to build your project"
            echo ""
            echo "  Android Emulator:"
            echo "    1. Run 'create-emulator' to create a new Pixel 7 API 34 emulator"
            echo "    2. Run 'start-emulator' to start emulator with software rendering"
            echo "    3. Run 'start-emulator-software' for pure software rendering (slower but stable)"
            echo "    4. Run 'start-emulator-headless' for headless testing"
            echo "    5. Run 'list-emulators' to see available emulators"
            echo "    6. Run 'delete-emulator' to delete the Pixel_7_API_36 emulator"
            echo ""
            echo "Platform support:"
            echo "  - Mobile: Android (SDK included)"
            echo "  - Desktop: Linux (GTK)"
            echo "  - Web: Chrome support included"
            echo "  - Rust: Full toolchain with cargo, rustfmt, clippy, and rust-analyzer"
            echo ""
          '';

          
        };

        # Formatter for the flake
        formatter = pkgs.nixpkgs-fmt;
      });
}
