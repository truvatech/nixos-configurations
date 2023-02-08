# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];

  # Use the systemd-boot EFI boot loader.
  boot = {
    loader = {
      systemd-boot.enable = true;
      efi.canTouchEfiVariables = true;
    };
    kernelPackages = pkgs.linuxPackages_6_1;
    extraModprobeConfig = "options kvm_intel nested=1";
    kernelParams = [ "intel_iommu=on" "vfio-pci.ids=10de:2204,10de:1aef" "i915.force_probe=a780" "default_hugepagesz=1G" "hugepagesz=1G" "hugepages=48" "vm.nr_hugepages=48" "nohugeiomap"];
    blacklistedKernelModules = [ "nvidia" "nouveau" ];
    initrd.kernelModules = [ "vfio_virqfd" "vfio_pci" "vfio_iommu_type1" "vfio" ];
  };
  networking = {
    hostName = "HOSTNAME";
    networkmanager.enable = true;
  };
  time.timeZone = "America/Toronto";
  #nix-store storage optimization
  nix.settings.auto-optimise-store = true;
  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Enable the X11 windowing system.
  #services.xserver = {
  #  enable = true;
    # Enable the Plasma 5 Desktop Environment.
  #  desktopManager.plasma5.enable = true;
  #  displayManager.sddm.enable = true;
  #};
  #systemd.targets."multi-user".conflicts = [ "getty@tty1.service" ];
  #nvidia
  #services.xserver.videoDrivers = [ "modesetting" ];
  #nixpkgs.config.allowUnfree = true;
  #hardware.opengl.enable = true;  

  #virt-manager
  virtualisation.libvirtd.enable = true;
  programs.dconf.enable = true;
  
  #filesystems
  fileSystems = {
    "/srv" = {
      device = "/dev/disk/by-uuid/DISK UUID TO REPLACE";
      fsType = "btrfs"; 
      options = [ "subvol=srv" "compress=zstd" ];
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
    "/swap".options = [ "noatime" ];
  };

  swapDevices = [ { device = "/swap/swapfile"; } ];
  # Enable CUPS to print documents.
  # services.printing.enable = true;
  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.USERNAME = {
    isNormalUser = true;
    extraGroups = [ "wheel" "libvirtd"]; # Enable ‘sudo’ for the user.
    openssh.authorizedKeys.keys = [
      (builtins.readFile ./key.pub)  #make sure you have your id_rsa.pub from your SSH client computer saved to /etc/nixos/key.pub
    ];
  #   packages = with pkgs; [
  #     firefox
  #     thunderbird
  #   ];
  };

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    nix-index
    pciutils
    (stdenv.mkDerivation {
      name = "virtiofsd-link";
      buildCommand = ''
        mkdir -p $out/bin
        ln -s ${pkgs.qemu}/libexec/virtiofsd $out/bin/
      '';
    })
    #vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
    #wget
  ];
  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  services.openssh = {
    enable = true;
    passwordAuthentication = false;
    permitRootLogin = "no";
  };
  #services.snapper = {
  #  snapshotRootOnBoot = true;
  #  snapshotInterval = "1d";
  #};
  services.btrbk = {
    instances."btrbk" = {
      onCalendar = "*:0";
      settings = {
        snapshot_preserve = "6h 7d";
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
        snapshot_preserve = "6h 7d";
        volume."/mnt/btrfs_srv" = {
          subvolume = "srv";
          snapshot_dir = ".snapshots";
        };
      };
    };
  };
  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;

  # Copy the NixOS configuration file and link it from the resulting system
  # (/run/current-system/configuration.nix). This is useful in case you
  # accidentally delete configuration.nix.
  # system.copySystemConfiguration = true;

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "22.11"; # Did you read the comment?

}

