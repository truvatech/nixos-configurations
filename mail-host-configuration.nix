# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, lib, ... }:
  
let release= "nixos-22.11"; #release version https://gitlab.com/simple-nixos-mailserver/nixos-mailserver
in {
  imports = [
    ./hardware-configuration.nix # Include the results of the hardware scan.
    ./radicale.nix
    (builtins.fetchTarball {
      url = "https://gitlab.com/simple-nixos-mailserver/nixos-mailserver/-/archive/${release}/nixos-mailserver-${release}.tar.gz";
      sha256 = "00000000000000000000000000000000000000"; #commit hash to replace with the proper hash after running nixos-rebuild once
    })
  ];
  boot.loader.grub.enable = true;
  boot.loader.grub.version = 2;
  boot.loader.grub.device = "/dev/sda"; 
  networking.hostName = "HOSTNAMECHANGEME";
  networking.networkmanager.enable = true;
  time.timeZone = "America/Toronto";
  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";
  security.acme = {
    defaults.email = "info@example.com";
    acceptTerms = true;
  };
  mailserver = {
    enable = true;
    fqdn = "mail.example.com";
    domains = [ "example.com" ];
    fullTextSearch = {
      enable = true;      
      autoIndex = true; #index new email as they arrive
      autoIndexExclude = ["Junk"];
      indexAttachments = true; #this only applies to plain text attachments, binary attachments are never indexed
      enforced = "body";
    };
    # A list of all login accounts. To create the password hashes, use
    # nix-shell -p mkpasswd --run 'mkpasswd -sm bcrypt'
    loginAccounts = {
        "emailaddress@example.com" = {
            hashedPasswordFile = "PATH/TO/HASHED/PASSWORD"; #make sure you save your hashed password somewhere
            aliases = ["info@example.com"];
        };
    };

    # Use Let's Encrypt certificates. Note that this needs to set up a stripped
    # down nginx and opens port 80.
    certificateScheme = 3;
    virusScanning = true;
    enableImap = false;
    enableSubmission = false;
  };

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.truva = {
    isNormalUser = true;
    extraGroups = [ "wheel" ]; # Enable ‘sudo’ for the user.
    openssh.authorizedKeys.keys = [
      (builtins.readFile ./key.pub) #make sure to have  your SSH client id_rsa.pub saved to  /etc/nixos/key.pub
    ];
  #   packages = with pkgs; [
  #     firefox
  #     thunderbird
  #   ];
  };

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  # environment.systemPackages = with pkgs; [
  #   vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
  #   wget
  # ];

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
  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;

  # Copy the NixOS configuration file and link it from the resulting system
  # (/run/current-system/configuration.nix). This is useful in case you
  # accidentally delete configuration.nix.
  system.copySystemConfiguration = true;

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "22.11"; # Did you read the comment?

}
