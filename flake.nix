{
  description = "Comail permissioned mailbox space host adapter";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.happyview-src = {
    url = "github:gamesgamesgamesgamesgames/happyview/f50b2afdaf207a2ba91d76cdad7a981a87785294";
    flake = false;
  };

  outputs = { self, nixpkgs, happyview-src }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          happyviewWeb = pkgs.buildNpmPackage {
            pname = "happyview-web";
            version = "2.13.0";
            src = "${happyview-src}/web";
            patches = [ ./patches/happyview-hermetic-system-fonts.patch ];
            npmDepsHash = "sha256-4sjYgU/tVGSy+pOl4hMCNMbYCYXYm3uoq9D4bxR0qv0=";
            env = {
              NEXT_PUBLIC_BASE_PATH = "/spaces";
              NEXT_PUBLIC_OAUTH_CLIENT_ID = "https://inbox.comail.at/spaces/oauth-client-metadata.json";
            };
            installPhase = ''
              runHook preInstall
              mkdir -p $out
              cp -R out/. $out/
              runHook postInstall
            '';
          };
          happyview = pkgs.rustPlatform.buildRustPackage {
            pname = "happyview";
            version = "2.13.0";
            src = happyview-src;
            patches = [ ./patches/happyview-service-auth-private-spaces.patch ];
            cargoHash = "sha256-AzabZcY7zu3qXI5RLJvE20d3ZVPqgD9cwwq0W6WFil8=";
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.openssl ];
            SQLX_OFFLINE = "true";
            HAPPYVIEW_VERSION = "2.13.0";
            doCheck = false;
            postInstall = ''
              mkdir -p $out/share/happyview
              cp -R migrations $out/share/happyview/migrations
              cp -R ${happyviewWeb} $out/share/happyview/web
            '';
            meta.mainProgram = "happyview";
          };
          comailSpaceHost = pkgs.buildGoModule {
            pname = "comail-space-host";
            version = "0.1.0";
            src = self;
            vendorHash = "sha256-zIzl44kD3oIZGvZsrCbcKTaHycaPMdKUzAtMR0SXxyU=";
            subPackages = [ "cmd/comail-space-host" ];
            doCheck = true;
            checkPhase = ''go test ./...'';
            meta.mainProgram = "comail-space-host";
          };
          comailSpacesBroker = pkgs.buildGoModule {
            pname = "comail-spaces-broker";
            version = "0.1.0";
            src = self;
            vendorHash = "sha256-zIzl44kD3oIZGvZsrCbcKTaHycaPMdKUzAtMR0SXxyU=";
            subPackages = [ "cmd/comail-spaces-broker" ];
            doCheck = true;
            checkPhase = ''go test ./...'';
            meta.mainProgram = "comail-spaces-broker";
          };
        in
        {
          default = comailSpaceHost;
          comail-space-host = comailSpaceHost;
          comail-spaces-broker = comailSpacesBroker;
          inherit happyview happyviewWeb;
        });

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.comail-space-host;
          brokerCfg = config.services.comail-spaces-broker;
          credentialDir = "/run/credentials/comail-space-host.service";
          brokerCredentialDir = "/run/credentials/comail-spaces-broker.service";
          configFile = pkgs.writeText "comail-space-host.json" (builtins.toJSON {
            inherit (cfg) listen providerOrigin serviceIssuerDid serviceAudience authorityCertificateSha256;
            serviceKeyFile = "${credentialDir}/service-key";
            relayTokenFile = "${credentialDir}/relay-token";
            evidenceFile = "${credentialDir}/provider-evidence";
            shutdownSeconds = 10;
          });
          brokerConfigFile = pkgs.writeText "comail-spaces-broker.json" (builtins.toJSON {
            enabled = true;
            inherit (brokerCfg) listen brokerOrigin returnUrl plcOrigin proofTimeoutSeconds shutdownSeconds;
            relayTokenFile = "${brokerCredentialDir}/relay-token";
            vaultFile = "/var/lib/comail-spaces-broker/oauth.vault";
            vaultKeyFile = "/var/lib/comail-spaces-broker/oauth-vault.key";
            inherit (brokerCfg) accounts;
          });
        in
        {
          options.services = {
            comail-space-host = {
              enable = lib.mkEnableOption "Comail permissioned mailbox adapter";
              package = lib.mkOption {
                type = lib.types.package;
                default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
                defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.default";
              };
              listen = lib.mkOption { type = lib.types.str; default = "127.0.0.1:39094"; };
              providerOrigin = lib.mkOption { type = lib.types.str; };
              serviceIssuerDid = lib.mkOption { type = lib.types.str; };
              serviceAudience = lib.mkOption { type = lib.types.str; };
              serviceKeyFile = lib.mkOption { type = lib.types.path; description = "Runtime source for the owner-only P-256 PKCS#8 key."; };
              relayTokenFile = lib.mkOption { type = lib.types.path; description = "Runtime source for the independent relay bearer token."; };
              authorityCertificateSha256 = lib.mkOption { type = lib.types.strMatching "[0-9a-f]{64}"; description = "Digest of the exact provider-epoch authority evidence."; };
              evidenceFile = lib.mkOption { type = lib.types.path; description = "Runtime source for owner-only provider-epoch authority evidence."; };
            };

            comail-spaces-broker = {
              enable = lib.mkEnableOption "production-dark Comail official Spaces onboarding broker";
              package = lib.mkOption {
                type = lib.types.package;
                default = self.packages.${pkgs.stdenv.hostPlatform.system}.comail-spaces-broker;
                defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.comail-spaces-broker";
              };
              listen = lib.mkOption { type = lib.types.str; default = "127.0.0.1:39095"; };
              brokerOrigin = lib.mkOption { type = lib.types.str; description = "Exact public HTTPS origin serving broker callbacks and metadata."; };
              returnUrl = lib.mkOption { type = lib.types.str; default = "https://comail.at/webmail/login"; };
              relayTokenFile = lib.mkOption { type = lib.types.path; description = "Runtime source for the independent relay-to-broker bearer."; };
              plcOrigin = lib.mkOption { type = lib.types.str; default = "https://plc.directory"; };
              proofTimeoutSeconds = lib.mkOption { type = lib.types.ints.between 1 60; default = 30; };
              shutdownSeconds = lib.mkOption { type = lib.types.ints.between 1 60; default = 10; };
              accounts = lib.mkOption {
                default = [ ];
                description = "Explicit official Spaces account and mailbox allowlist.";
                type = lib.types.listOf (lib.types.submodule {
                  options = {
                    did = lib.mkOption { type = lib.types.str; };
                    handle = lib.mkOption { type = lib.types.str; };
                    pdsOrigin = lib.mkOption { type = lib.types.str; };
                    spaceHostOrigin = lib.mkOption { type = lib.types.str; };
                    spaceKey = lib.mkOption { type = lib.types.str; default = "primary"; };
                    provisioningMetadataPath = lib.mkOption { type = lib.types.str; };
                    steadyMetadataPath = lib.mkOption { type = lib.types.str; };
                  };
                });
              };
            };
          };

          config = lib.mkMerge [
            (lib.mkIf cfg.enable {
              assertions = [
                { assertion = lib.hasPrefix "https://" cfg.providerOrigin; message = "comail-space-host providerOrigin must use HTTPS"; }
              ];
              systemd.services.comail-space-host = {
                description = "Comail permissioned mailbox adapter";
                wantedBy = [ "multi-user.target" ];
                after = [ "network-online.target" ];
                wants = [ "network-online.target" ];
                serviceConfig = {
                  ExecStart = "${lib.getExe cfg.package} --config ${configFile}";
                  LoadCredential = [
                    "service-key:${toString cfg.serviceKeyFile}"
                    "relay-token:${toString cfg.relayTokenFile}"
                    "provider-evidence:${toString cfg.evidenceFile}"
                  ];
                  DynamicUser = true;
                  Restart = "on-failure";
                  RestartSec = "5s";
                  NoNewPrivileges = true;
                  PrivateTmp = true;
                  PrivateDevices = true;
                  ProtectSystem = "strict";
                  ProtectHome = true;
                  ProtectKernelTunables = true;
                  ProtectKernelModules = true;
                  ProtectControlGroups = true;
                  RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
                  RestrictSUIDSGID = true;
                  LockPersonality = true;
                  MemoryDenyWriteExecute = true;
                  UMask = "0077";
                };
              };
            })
            (lib.mkIf brokerCfg.enable {
              assertions = [
                { assertion = lib.hasPrefix "https://" brokerCfg.brokerOrigin; message = "comail-spaces-broker brokerOrigin must use HTTPS"; }
                { assertion = brokerCfg.returnUrl == "https://comail.at/webmail/login"; message = "comail-spaces-broker returnUrl is fixed"; }
                { assertion = brokerCfg.accounts != [ ]; message = "comail-spaces-broker requires an explicit non-empty account allowlist"; }
                {
                  assertion = lib.all (account: lib.hasPrefix "https://" account.pdsOrigin && account.spaceHostOrigin == account.pdsOrigin) brokerCfg.accounts;
                  message = "comail-spaces-broker accounts require one exact shared HTTPS PDS/space-host origin";
                }
              ];
              systemd.services.comail-spaces-broker = {
                description = "Comail official Spaces onboarding broker";
                wantedBy = [ "multi-user.target" ];
                after = [ "network-online.target" ];
                wants = [ "network-online.target" ];
                serviceConfig = {
                  ExecStart = "${lib.getExe brokerCfg.package} --config ${brokerConfigFile}";
                  LoadCredential = [ "relay-token:${toString brokerCfg.relayTokenFile}" ];
                  StateDirectory = "comail-spaces-broker";
                  StateDirectoryMode = "0700";
                  DynamicUser = true;
                  Restart = "on-failure";
                  RestartSec = "5s";
                  NoNewPrivileges = true;
                  PrivateTmp = true;
                  PrivateDevices = true;
                  ProtectSystem = "strict";
                  ProtectHome = true;
                  ProtectKernelTunables = true;
                  ProtectKernelModules = true;
                  ProtectControlGroups = true;
                  ProtectHostname = true;
                  ProtectClock = true;
                  RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
                  RestrictSUIDSGID = true;
                  RestrictRealtime = true;
                  LockPersonality = true;
                  MemoryDenyWriteExecute = true;
                  CapabilityBoundingSet = "";
                  AmbientCapabilities = "";
                  SystemCallArchitectures = "native";
                  UMask = "0077";
                };
              };
            })
          ];
        };
    };
}
