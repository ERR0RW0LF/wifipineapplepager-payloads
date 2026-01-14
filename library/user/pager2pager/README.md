# P2P Pager

## Description
P2P Pager is an implementation of an idea Darren had whilst streaming.

It's a pager system for the WiFi Pineapple Pager which uses Access Points to send messages to other pagers in the same "network", a so to say pager to pager system. And repeating the messages to have a bigger range.

## Author

ERR0RW0LF

## Credits

- Darren Kitchen - Original idea and inspiration.
- PentestPlaybook - For the inspiration of the structure of the payloads and documentation.

## Payloads

| Payload | Description |
| ------- | ----------- |
| install_ap_pager | Installs the AP Pager service. |
| enable_ap_pager | Enables the AP Pager service to start on boot. |
| disable_ap_pager | Disables the AP Pager service from starting on boot. |
| start_ap_pager | Starts the AP Pager service. |
| stop_ap_pager | Stops the AP Pager service. |
| restart_ap_pager | Restarts the AP Pager service. |
| config_ap_pager | Configures the AP Pager service. |


## How it works
The P2P Pager works by creating a beacon frame with the message embedded in an IE (Information Element), with the tag 221 (Vendor Specific). Other pagers in range will pick up the beacon frames, extract the message, and rebroadcast it to extend the range.

To avoid message flooding, each pager keeps track of the messages it has already seen and will not rebroadcast the same message more than once.

A pager automatically rebroadcasts any new messages it receives, for 10 seconds after starting sending. By a default delay of 0.102 seconds between each beacon frame, it sends approximately 98 beacons in that time.
