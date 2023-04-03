{ config, pkgs, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];
  boot = {
    loader = {
      systemd-boot.enable = true;
      efi.canTouchEfiVariables = true;
    };
    kernelPackages = pkgs.linuxPackages_6_1;
    extraModprobeConfig = "options kvm_intel nested=1";
    kernelParams = [ "intel_iommu=on" "vfio-pci.ids=10de:2204,10de:1aef" "i915.force_probe=a780" "default_hugepagesz=1Gi" "hugepages=48" ];
    blacklistedKernelModules = [ "nvidia" "nouveau" ];
    initrd.kernelModules = [ "vfio_virqfd" "vfio_pci" "vfio_iommu_type1" "vfio" ];
  };
  networking = {
    hostName = "captain";
    networkmanager.enable = true;
    firewall = {
      allowedTCPPorts = [ 80 443 ];
      extraCommands = ''
        iptables -A nixos-fw -p tcp --source 10.0.0.0/24 --dport 2368:2368 -j nixos-fw-accept
       # iptables -A nixos-fw -p udp --source 10.0.0.0/24 --dport port:port -j nixos-fw-accept
      '';
      extraStopCommands = ''
        iptables -D nixos-fw -p tcp --source 10.0.0.0/24 --dport 2368:2368 -j nixos-fw-accept || true
       # iptables -D nixos-fw -p udp --source 10.0.0.0/24 --dport port:port -j nixos-fw-accept || true
      '';
    };
    wg-quick.interfaces = {
      wg0 = {
        address = [ "10.0.0.2/32" ];
        dns = [ "10.0.0.1" ];
        privateKeyFile = "/home/truva/wireguard-keys/private";
        peers = [
          {
            publicKey = ""; #add your wireguard peer's public key
            presharedKeyFile = "/home/truva/wireguard-keys/captain.psk";
            allowedIPs = [ "0.0.0.0/0" ];
            endpoint = "vpn.example.com:port"; #peer's publicly accesible domain name or IP address 
            persistentKeepalive = 25;
          }
        ];
      };
    };
  };
  time.timeZone = "America/Toronto";
  nix.settings.auto-optimise-store = true;

  # xserver service kept in case of GPU removal/debugging server through onboard HDMI output - onboard GPU can be disabled/enabled in BIOS
  #services.xserver = {
  #  enable = true;
    # Enable the Plasma 5 Desktop Environment.
  #  desktopManager.plasma5.enable = true;
  #  displayManager.sddm.enable = true;
  #};
  #needed for proper loading of nvidia before tty1 (doesn't apply to every build but was an issue with mine)
  #systemd.targets."multi-user".conflicts = [ "getty@tty1.service" ];
  #set nvidia or modesetting driver
  #services.xserver.videoDrivers = [ "modesetting" ];
  # needed for nvidia driver
  #nixpkgs.config.allowUnfree = true;
  #hardware.opengl.enable = true;  

  #virt-manager
  virtualisation = {
    libvirtd.enable = true;
    oci-containers = {
      backend = "podman";
      containers = {
        ghost = {
          image = "ghost:5.40.2-alpine";
          autoStart = true;
          ports = [ "127.0.0.1:2368:2368" ];
          environment = {
            database__client = "mysql";
            database__connection__host = "localhost";
 #           database__connection__port = "3306";
            database__connection__user = "ghost";
            database__connection__password = ""; #DB password
            database__connection__database = "ghost";
            url = "https://ghost.example.com"; #ghost public URL
            privacy__useTinfoil = "true"; #no crawling/social media integrations
          };
          extraOptions = [ "--network=host" ];
        };
      };
    };
  };
  programs.dconf.enable = true;
  fileSystems = {
    "/srv" = {
      device = "/dev/disk/by-uuid/243cc6ed-13ca-41fe-9499-af40fe5f2a97";
      fsType = "btrfs"; 
      options = [ "subvol=srv" "compress=zstd" ];
    };
    "/swap" = {
      device = "/dev/disk/by-uuid/9d174047-4739-4574-b896-02d48db179c0";
      fsType = "btrfs"; 
      options = [ "subvol=swap" "noatime"];
    };
    "/mnt/btrfs_root" = {
      device = "/dev/nvme0n1p1";
      fsType = "btrfs";
      options = [ "subvolid=5" ];
    };
    "/mnt/btrfs_srv" = {
      device = "/dev/nvme0n1p6";
      fsType = "btrfs";
      options = [ "subvolid=5" ];
    };  
    "/".options = [ "compress=zstd" ];
    "/home".options = [ "compress=zstd" ];
    "/nix".options = [ "compress=zstd" "noatime" ];
  };

  swapDevices = [ { device = "/swap/swapfile"; } ];
  users.users.truva = {
    isNormalUser = true;
    extraGroups = [ "wheel" "libvirtd" ]; # Enable ‘sudo’ for the user and access to libvirtd.
    openssh.authorizedKeys.keyFiles = [
      #public keys from ~/.ssh/id_rsa.pub on clients kept in /etc/nixos/key.pub
      ./key.pub
    ];
  };

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    nix-index
    pciutils
    (stdenv.mkDerivation { #this is a fix for virtioFS as it wasn't finding the bin file
      name = "virtiofsd-link";
      buildCommand = ''
        mkdir -p $out/bin
        ln -s ${pkgs.qemu}/libexec/virtiofsd $out/bin/
      '';
    })
    dig
    lm_sensors
    traceroute
    ffmpeg #needed for nextcloud thumbnail generation
  ];

  # List services that you want to enable:
  services = {
    openssh = {
      enable = true;
      passwordAuthentication = false;
      permitRootLogin = "no";
    };
    btrbk = {
      instances."btrbk" = {
        onCalendar = "*:0";
        settings = {
          snapshot_preserve = "24h 7d";
	  snapshot_preserve_min = "6h";
          volume."/mnt/btrfs_root" = {
            subvolume = {
              "root" = { snapshot_create = "always"; };
              "nix" = { snapshot_create = "always"; };
              "home" = { snapshot_create = "always"; };
            };
            snapshot_dir = ".snapshots";
          };
        };
      };
      instances."srv" = {
        onCalendar = "*:0";
        settings = {
          snapshot_preserve = "24h 7d";
          snapshot_preserve_min = "6h";
          volume."/mnt/btrfs_srv" = {
            subvolume = {
              "srv" = { snapshot_create = "always"; };
            };
            snapshot_dir = ".snapshots";
          };
        };
      };
    };
    vsftpd = {
      enable = true;
      #forceLocalLoginsSSL = true;
      #forceLocalDataSSL = true;
      userlistDeny = false;
      localUsers = true;
      userlist = [ "truva" ];
      #rsaKeyFile = "/etc/nixos/key.pub";
    };
    mysql = {
      enable = true;
      package = pkgs.mariadb;
      ensureDatabases = [ "nextcloud" "ghost" ];
      dataDir = "/srv/db/mysql";
      ensureUsers = [
        { name = "nextcloud";
          ensurePermissions."nextcloud.*" = "ALL PRIVILEGES";
        }
        { name = "ghost";
          ensurePermissions."ghost.*" = "ALL PRIVILEGES";
        } 
      ];
      settings = {
        mysqld = {
          bind-address = "localhost";
          key_buffer_size = "6G";
          table_cache = 1600;
          log-error = "/var/log/mysql/mysql_err.log";
        };
        mysqldump = {
          quick = true;
          max_allowed_packet = "16M";
        };
      };
    };
    postgresql = {
      enable = true;
      ensureDatabases = [ "nextcloud" ];
      ensureUsers = [
        { name = "nextcloud";
          ensurePermissions."DATABASE nextcloud" = "ALL PRIVILEGES";
        }
      ];
    };
    nextcloud = {
      enable = true;
      package = pkgs.nextcloud25;
      hostName = "nextcloud.example.com"; #nextcloud URL
      home = "/srv/nextcloud";
      extraApps = with pkgs.nextcloud25Packages.apps; {
         inherit news bookmarks deck notes tasks twofactor_totp;
      };
      extraAppsEnable = true;
      config ={
        trustedProxies = [ "10.0.0.1" ];
        overwriteProtocol = "https";
        adminpassFile = "${pkgs.writeText "adminpass" "test123"}"; #set initial admin password here - change after first log in
        dbtype = "pgsql";
        dbuser = "nextcloud";
        dbhost = "/run/postgresql"; # nextcloud will add /.s.PGSQL.5432 by itself
        dbname = "nextcloud";
        defaultPhoneRegion = "CA";
      };
      https = true;
      autoUpdateApps.enable = true;
      extraOptions =  {
        enable_previews = true;
        enabledPreviewProviders = [ 
          "OC\\Preview\\Movie"
          "OC\\Preview\\PNG"
          "OC\\Preview\\JPEG"
          "OC\\Preview\\GIF"
          "OC\\Preview\\BMP"
          "OC\\Preview\\XBitmap"
          "OC\\Preview\\MP3"
          "OC\\Preview\\MP4"
          "OC\\Preview\\TXT"
          "OC\\Preview\\MarkDown"
          "OC\\Preview\\PDF"
        ];
      };
    };
    grafana = {
      enable = true;
      settings.server = {
        domain = "captain.ymr";
        http_port = 2342;
        http_addr = "127.0.0.1";
      };
    };
    nginx.virtualHosts.${config.services.grafana.settings.server.domain} = {
      locations."/" = {
        proxyPass = "http://127.0.0.1:${toString config.services.grafana.settings.server.http_port}";
        proxyWebsockets = true;
        extraConfig = ''
          proxy_set_header Host $host;
        ''; 
      };
    };
    prometheus = {
      enable = true;
      port = 9001;
      exporters = {
        node = {
          enable = true;
          enabledCollectors = [ "systemd" "hwmon" ];
          port = 9002;
        };
      };
      scrapeConfigs = [
        {
          job_name = "captain";
          static_configs = [{
            targets = [ "127.0.0.1:${toString config.services.grafana.settings.server.http_port}" ];
          }];
        }
      ];
    };
  };
  systemd.services."nextcloud-setup" = {
    requires = ["postgresql.service"];
    after = ["postgresql.service"];
  };
  system.stateVersion = "22.11"; # Did you read the comment?
}
