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
    in {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          happyviewWeb = pkgs.buildNpmPackage {
            pname = "happyview-web";
            version = "2.13.0";
            src = "${happyview-src}/web";
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
            cargoHash = "sha256-AzabZcY7zu3qXI5RLJvE20d3ZVPqgD9cwwq0W6WFil8=";
            SQLX_OFFLINE = "true";
            HAPPYVIEW_VERSION = "2.13.0";
            doCheck = false;
            postInstall = ''
              mkdir -p $out/share/happyview
              cp -R migrations $out/share/happyview/migrations
              cp -R ${happyviewWeb} $out/share/happyview/web
            '';
          };
        in {
          default = pkgs.buildGoModule {
            pname = "comail-space-host";
            version = "0.1.0";
            src = self;
            vendorHash = "sha256-LNTxUH9AQfm43xtyOW1O1Kp2J/CqvNWPZJ/HDrvv43U=";
            subPackages = [ "cmd/comail-space-host" ];
            doCheck = true;
            checkPhase = ''go test ./...'';
            meta.mainProgram = "comail-space-host";
          };
          inherit happyview happyviewWeb;
        });

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.comail-space-host;
          credentialDir = "/run/credentials/comail-space-host.service";
          mailboxJSON = mailbox: {
            inherit (mailbox) did spaceKey authorityCertificateSha256;
            evidenceFile = "${credentialDir}/evidence-${mailbox.credentialName}";
          };
          configFile = pkgs.writeText "comail-space-host.json" (builtins.toJSON {
            inherit (cfg) listen providerOrigin serviceIssuerDid serviceAudience;
            serviceKeyFile = "${credentialDir}/service-key";
            relayTokenFile = "${credentialDir}/relay-token";
            mailboxes = map mailboxJSON cfg.mailboxes;
            shutdownSeconds = 10;
          });
        in {
          options.services.comail-space-host = {
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
            mailboxes = lib.mkOption {
              default = [];
              type = lib.types.listOf (lib.types.submodule ({ ... }: {
                options = {
                  did = lib.mkOption { type = lib.types.str; };
                  spaceKey = lib.mkOption { type = lib.types.str; default = "default"; };
                  authorityCertificateSha256 = lib.mkOption { type = lib.types.str; };
                  credentialName = lib.mkOption { type = lib.types.strMatching "[a-z0-9-]+"; };
                  evidenceFile = lib.mkOption { type = lib.types.path; description = "Runtime source for owner-only authority evidence."; };
                };
              }));
            };
          };

          config = lib.mkIf cfg.enable {
            assertions = [
              { assertion = lib.hasPrefix "https://" cfg.providerOrigin; message = "comail-space-host providerOrigin must use HTTPS"; }
              { assertion = cfg.mailboxes != []; message = "comail-space-host requires at least one explicit mailbox"; }
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
                ] ++ map (mailbox: "evidence-${mailbox.credentialName}:${toString mailbox.evidenceFile}") cfg.mailboxes;
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
          };
        };
    };
}
