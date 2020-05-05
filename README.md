# Introduction

DATP-to-EIQ is a simple Python script that will:

1. connect to your Windows Defender ATP and Microsoft Security Center instances;
2. download all events that occurred within the given time window;
3. import them into your EclecticIQ instance as Sighting or Incident entities.

For configuration options, refer to the `settings.py.sample` file in the `config` directory.

# Requirements

- Python 3
- EIQlib module (https://github.com/KPN-CISO/eiqlib)
- Microsoft Azure AD, Defender ATP API access (with SIEM connector permissions)
- Graph API credentials to generate Graph API tokens
- An EclecticIQ account (user+pass) and EIQ 'Source' token

# Getting started

- Clone the repository
- Rename the `settings.py.sample` file in the `config` directory to `settings.py` 
- Edit the settings in the `settings.py` file to reflect your environment
- Run ./datp_to_eiq.py -h for help/options

# Options

Running ./datp-to-eiq.py with `-h` will display help:  

`-v` / `--verbose` will display progress/error info  
`-s` / `--simulate` do not actually ingest anything into EclecticIQ, just pretend (useful with `-v`)  
`-d` / `--duplicate` do not update the existing entity in EclecticIQ, but create duplicates (default: disabled)  

# Copyright

(c) 2020 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl> 

This software is GPLv3 licensed, except where otherwise indicated.
