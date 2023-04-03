{ config, pkgs, lib, ... }:
  
let release= "nixos-22.11"; #release version https://gitlab.com/simple-nixos-mailserver/nixos-mailserver
in {
  imports = [
    ./hardware-configuration.nix # Include the results of the hardware scan.
    ./radicale.nix
    (builtins.fetchTarball {
      url = "https://gitlab.com/simple-nixos-mailserver/nixos-mailserver/-/archive/${release}/nixos-mailserver-${release}.tar.gz";
      sha256 = "1h1r4x2ffqwyk0ql6kjvcpg1bdiimyzhrsvn49702fsgzpx57fhd"; #commit hash, can be all zeros for the first time you run this and it will return the correct hash to update the file with
    })
  ];
  boot.loader.grub ={
    enable = true;
    version = 2;
    device = "/dev/sda"; 
  };
  time.timeZone = "America/Toronto";
  networking ={
    hostName = "mail";
    networkmanager = {
      enable = true;
      dns = "none";
    };
    #enableIPv6 = false;
    defaultGateway = {
      interface = "enp1s0";
      address = "x.x.x.x"; #VPS gateway address - check default route in "ip route show": "default via x.x.x.x"
    };
    interfaces.enp1s0.ipv4.addresses = [ 
      { address = "x.x.x.x"; prefixLength = 24; }  #primary IP address (for mailserver)
      { address = "x.x.x.x"; prefixLength = 24; }  #secondary IP address (for vpn traffic)
    ];
    nat = {
      enable = true;
      enableIPv6 = false;
      externalInterface = "enp1s0";
      internalInterfaces = [ "wg0" ];
      # internalIPs = [ "10.0.0.1/24" ];
      externalIP = "x.x.x.x"; #secondary IP address on instance to seperate VPN IP address from mailserver IP address
    };
    # Open ports in the firewall
    firewall = {
      allowedTCPPorts = [ 53 80 443 ];
      allowedUDPPorts = [ 53 wireguard-port ];#chagne wg port to port value
      extraCommands = ''
      # iptables -A nixos-fw -p tcp --source 10.0.0.0/24  -j nixos-fw-accept
      # iptables -A nixos-fw -p udp --source 10.0.0.0/24  -j nixos-fw-accept
        iptables --table nat --flush OUTPUT
        ${lib.flip (lib.concatMapStringsSep "\n") [ "udp" "tcp" ] (proto: ''
          iptables --table nat --append OUTPUT \
            --protocol ${proto} --destination 127.0.0.1 --destination-port 53 \
            --jump REDIRECT --to-ports 51
        '')}
      '';
    };
    wg-quick.interfaces = {
    #personal VPN
      wg0 = {
        address = [ "10.0.0.1/24" ];
        listenPort = PORT; #change to port value
        privateKeyFile = "/home/truva/wireguard-keys/private";
        postUp = ''
          ${pkgs.iptables}/bin/iptables -A FORWARD -i wg0 -j ACCEPT
        '';
        preDown = ''
          ${pkgs.iptables}/bin/iptables -D FORWARD -i wg0 -j ACCEPT
        '';

        peers = [
          { # captain
            publicKey = "sSp6r/JEFjXkY*************";
            presharedKeyFile = "/home/truva/wireguard-keys/captain.psk";
            allowedIPs = [ "10.0.0.2/32" ];
          }
          { # command
            publicKey = "QJ1QdaHT*************";
            presharedKeyFile = "/home/truva/wireguard-keys/command.psk";
            allowedIPs = [ "10.0.0.3/32" ];
          }
          { # pixel
            publicKey = "M2VIiU*************";
            allowedIPs = [ "10.0.0.4/32" ];
          }
          { # giga
            publicKey = "4eKpk/*************";
            presharedKeyFile = "/home/truva/wireguard-keys/giga.psk";
            allowedIPs = [ "10.0.0.5/32" ];
          }
          { # g5 pao
            publicKey = "3DQimO*************";
            presharedKeyFile = "/home/truva/wireguard-keys/g5.psk";
            allowedIPs = [ "10.0.0.6/32" ];
          }
          # More peers can be added here.
        ];
      };
    # More wireguard interfaces can be added here.
    };
    extraHosts = ''
      10.0.0.1 cloudnix.ymr
      10.0.0.1 cal.cloudnix.ymr
      10.0.0.2 captain.ymr
      10.0.0.3 command.ymr
      x.x.x.x mail.example.com mail #mailserver's public IP address
    '';
    nameservers = [ "127.0.0.1" ];
  };
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
      autoIndexExclude = [ "Junk" ];
      indexAttachments = true; #this only applies to plain text attachments, binary attachments are never indexed
      enforced = "body";
    };
    # A list of all login accounts. To create the password hashes, use
    # nix-shell -p mkpasswd --run 'mkpasswd -sm bcrypt'
    loginAccounts = {
        "user@example.com" = {
            hashedPasswordFile = "/etc/nixos/emailpasswd";
            aliases = ["info@example.com"];
        };
        "nextcloud@example.com" = {
            hashedPasswordFile = "/etc/nixos/nextcloudemail";
            
        };
    };
    certificateScheme = 3;    
    virusScanning = false;
    enableImap = false;
    enableImapSsl = true;
    enableSubmission = false;
    localDnsResolver = false;
    rebootAfterKernelUpgrade.enable = true;
    monitoring.alertAddress = "info@example.com";
    monitoring.enable = true;
  };
  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.truva = {
    isNormalUser = true;
    extraGroups = [ "wheel" ]; # Enable ‘sudo’ for the user.
    openssh.authorizedKeys.keyFiles = [
      ./key.pub
    ];
  };
  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    dig
    traceroute
  ];
  services = {
    openssh = {
      enable = true;
      passwordAuthentication = false;
      permitRootLogin = "no";
    };
    dnsmasq = {
      enable = true;
      extraConfig = ''
        interface=wg0
        server=127.0.0.1#51
        clear-on-reload
      '';
    };
    qemuGuest.enable = true;
    vsftpd = {
      enable = false;
      #forceLocalLoginsSSL = true;
      #forceLocalDataSSL = true;
      userlistDeny = false;
      localUsers = true;
      userlist = ["truva"];
      #rsaCertFile = "/var/vsftpd/vsftpd.pem";
    };
    dnscrypt-proxy2 = {
      enable = true;
      settings = {
        require_dnssec = true;
        block_ipv6 = true;
        ipv6_servers = false;
        listen_addresses = [ "127.0.0.1:51" ];
        sources.public-resolvers = {
          urls = [
            "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md"
            "https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md"
          ];
          cache_file = "/var/lib/dnscrypt-proxy2/public-resolvers.md";
          minisign_key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
        };
        server_names = [ "quad9-forced-secondary" "quad9-dnscrypt-ip4-filter-pri" "cloudflare-security"  ];
        static.quad9-forced-secondary = {
          stamp = "sdns://AQMAAAAAAAAAFDE0OS4xMTIuMTEyLjExMjo4NDQzIGfIR7jIdYzRICRVQ751Z0bfNN8dhMALjEcDaN-CHYY-GTIuZG5zY3J5cHQtY2VydC5xdWFkOS5uZXQ";
        };
      };
    };
    stubby = {
      enable = true;
      settings = {
        resolution_type = "GETDNS_RESOLUTION_STUB";
        dns_transport_list =  [ "GETDNS_TRANSPORT_TLS" ];
        dnssec_return_status = "GETDNS_EXTENSION_TRUE";
        tls_authentication = "GETDNS_AUTHENTICATION_REQUIRED";
        tls_query_padding_blocksize = 256;
        edns_client_subnet_private = 1;
        idle_timeout = 10000;
        listen_addresses = [ "127.0.0.1" ];
        round_robin_upstreams = 1;
        upstream_recursive_servers = [{
          address_data = "149.112.112.112";
          tls_auth_name = "dns.quad9.net";
          tls_pubkey_pinset = {
            digest = "sha256";
            value = "MujBQ+U0p2eZLTnQ2KGEqs+fPLYV/1DnpZDjBDPwUqQ=";
          };
        }];
      };
    };
    nginx = {
      enable = true;
      recommendedProxySettings = true;
      recommendedTlsSettings = true;
      recommendedGzipSettings = true;
      recommendedOptimisation = true;
      sslCiphers = "AES256+EECDH:AES256+EDH:!aNULL";
      sslProtocols = "TLSv1.3";
      virtualHosts."nextcloud.example.com" =  {
        enableACME = true;
        forceSSL = true;
        locations."/" = {
          proxyPass = "http://10.0.0.2/";
        };
      };
      virtualHosts."ghost.example.com" =  {
        enableACME = true;
        forceSSL = true;
        locations."/" = {
          proxyPass = "http://captain.ymr:2368";
        };
      };
      virtualHosts."uptime.example.com" =  {
        enableACME = true;
        forceSSL = true;
        locations."/" = {
          proxyPass = "http://localhost:3001/";
          proxyWebsockets = true;
        };
      };
      virtualHosts."mail.example.com" =  {
        enableACME = true;
        forceSSL = true;
        locations."/" = {
          return  = "301 http://www.example.com/";
        };
      };
      virtualHosts."vpn.example.com" =  {
        enableACME = true;
        forceSSL = true;
        locations."/" = {
          return  = "301 http://www.example.com/";
        };
      };
      commonHttpConfig = 
      let
        realIpsFromList = lib.strings.concatMapStringsSep "\n" (x: "set_real_ip_from  ${x};");
        fileToList = x: lib.strings.splitString "\n" (builtins.readFile x);
        cfipv4 = fileToList (pkgs.fetchurl {
          url = "https://www.cloudflare.com/ips-v4";
          sha256 = "0ywy9sg7spafi3gm9q5wb59lbiq0swvf0q3iazl0maq1pj1nsb7h";
        });
        cfipv6 = fileToList (pkgs.fetchurl {
          url = "https://www.cloudflare.com/ips-v6";
          sha256 = "1ad09hijignj6zlqvdjxv7rjj8567z357zfavv201b9vx3ikk7cy";
        });
      in
      ''
        ${realIpsFromList cfipv4}
        ${realIpsFromList cfipv6}
        real_ip_header CF-Connecting-IP;
      '';     
    };
    prometheus = {   #WIP
      #enable = true; #disabled to work on this later
      #port = 9001;
      exporters = {
        node = {
          enable = true;
          enabledCollectors = [ "systemd" ];
          port = 9002;
        };
      };
      scrapeConfigs = [
        {
          job_name = "cloudnix.ymr";
          static_configs = [{
            targets = [ "captain.ymr:2342" ];
          }];
        }
      ];
    };
    fail2ban = {
      enable = true;
      ignoreIP = [
       "10.0.0.0/24" #wireguard clients
       "x.x.x.x" #vpn/client's public IP address
        "x.x.x.x" #this mailhost address
      ];
      maxretry = 2;
      bantime-increment = {
        enable = true;
        maxtime = "7d";
      };
      jails = {
        DEFAULT = ''
          bantime = 86400
        '';
        dovecot = ''
          enabled = true
          filter = dovecot[mode=aggressive]
        '';
        postfix = ''
          enabled = true
          port = smtp,465,submission
          filter   = postfix[mode=aggressive]
        '';
      };
    };
    jitsi-meet = {
      enable = false; #set to false unless needed, otherwise gets spammed by bots (setting up security on this is in my backlog)
      hostName = "meet.example.com";
      config = {
        enableWelcomePage = false;
        prejoinPageEnabled = true;
        defaultLang = "en";
      };
      interfaceConfig = {
        SHOW_JITSI_WATERMARK = false;
        SHOW_WATERMARK_FOR_GUESTS = false;
      };
    };
    uptime-kuma = {
      enable = true;
      settings.port = "3001";
    };
  };
  systemd.services.dnscrypt-proxy2.serviceConfig = {
    StateDirectory = "dnscrypt-proxy";
  };
  system = {
    copySystemConfiguration = true;
    stateVersion = "22.11"; # Did you read the comment?
  };
}
