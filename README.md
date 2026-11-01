
<center>

# PrivacyLRS
PrivacyLRS is a privacy-protecting fork of the excellent [ExpressLRS (ELRS)](https://www.expresslrs.org/) long-range RC system.
PrivacyLRS is for those who want to use telemetry, but not broadcast their GPS location and other telemetry for 
other people to read.

With *standard* ELRS, it is inconvenient for others to read your telemetry link - they would need to work for it a little bit.
PrivacyLRS uses strong encryption to make it *impossible* for other people to read your telemetry and get your location
that way, among other information.

RC commands are also encrypted.

## FAQ
### How do the performance and features compare?  
  Performance and features of PrivacyLRS are identical for the same version number of ELRS, because PrivacyLRS is the exact same code as ELRS - just with the packets encrypted.
  The encryption is much, much faster than the radio link, so there is no effectively no delay.
  To put that into hard numbers, at at 250 Hz, that's a minimum of 4 milliseconds between packets (without encryption)
  ● Time between packets at 250 Hz:
  - Frequency = 250 packets/second
  - Time per packet = 1 / 250 = 4 milliseconds

  ChaCha20 encryption Encryption time: 0.00352 milliseconds
  - Percentage: (0.00352 / 4) × 100 = 0.088%

  So you have 4 milliseconds between each packet, and ChaCha20 encryption only uses 0.00352 milliseconds of that time, which is 0.088% (less
  than 1/10th of 1 percent).


### How do I use PrivacyLRS?  
  Download the [zip file](https://github.com/sensei-hacker/PrivacyLRS/archive/refs/heads/secure_01.zip) of the secure branch.
  Unzip it, then flash using ELRS Configurator by choosing "Local" as shown in this screenshot:
  ![image of local tab in Configurator](https://raw.githubusercontent.com/sensei-hacker/PrivacyLRS/secure_01/src/privacylrs/screenshot_choose_local.png)

### Is this a fork because somebody got mad?  
  The maintainer of PrivacyLRS has nothing but love for ExpressLRS and the ELRS maintainers. I simply wanted a version that protects my privacy.

## Status of the project and testing
PrivacyLRS is currently in beta - testers needed. The encryption is stateless, so it cannot get out of sync the way earlier
versions could, but this has not yet been tested in flight. See [ENCRYPTION_RELIABILITY.md](ENCRYPTION_RELIABILITY.md) for
the issues found in earlier versions, what changed, and which tests are still needed on hardware.
Radio performance (range, sensitivity) should match standard ELRS, but reconnecting may take slightly longer at some packet rates.
\* If standard ELRS has latency of 6.522ms at a certain packet rate, PrivacyLRS will have latency of around 6.525ms - the
the difference probably being too small to measure.
If you choose to test PrivacyLRS, be sure to set up your failsafe carefully. Bugs could cause the link to fail.

## Differences between ELRS and PrivacyLRS
The ELRS documentation makes clear that the binding phrase is *not* a security feature in standard ELRS.
In standard ELRS, the binding phrase is to prevent *accidental* conflicts between two aircraft.
This is different in PrivacyLRS. In PrivacyLRS, the encryption key is derived from the bind phrase, so **the bind phrase is the
only secret protecting your link**. Use 5 or more random words, and build your transmitter and receiver with the same phrase.
Anyone who learns your phrase, or reads the firmware from a lost aircraft, can read your link, including past recordings.
If you fully erase the transmitter's flash, choose a new phrase.

PrivacyLRS hides your telemetry and RC commands from anyone listening. Like standard ELRS, it does not authenticate packets,
so it does not stop someone deliberately jamming or disrupting your link.


## About ExpressLRS


ExpressLRS is an open source Radio Link for Radio Control applications. Designed to be the best FPV Racing link, it is based on the fantastic Semtech **SX127x**/**SX1280** LoRa hardware combined with an Espressif or STM32 Processor. Using LoRa modulation as well as reduced packet size it achieves best in class range and latency. It achieves this using a highly optimized over-the-air packet structure, giving simultaneous range and latency advantages. It supports both 900 MHz and 2.4 GHz links [also 433 and 868], each with their own benefits. 900 MHz supports a maximum of 200 Hz packet rate, with higher penetration. 2.4 GHz supports a blistering fast 1000 Hz on [EdgeTX](http://edgetx.org/). With over 60 different hardware targets and 13 hardware manufacturers, the choice of hardware is ever growing, with different hardware suited to different requirements.


## Configurator
To configure your ExpressLRS / PrivacyLRS hardware, the ExpressLRS Configurator can be used, which is found here:

https://github.com/ExpressLRS/ExpressLRS-Configurator/releases/

