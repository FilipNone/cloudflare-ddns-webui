# Roadmap

Known follow-ups, roughly in order.

## Next

### UI

- [ ] Change domain field from domain to destination in the CNAME add record popup.
- [ ] Change flags field from flags to flag in the CAA add record popup.
- [ ] Inside the fields (Name, IPv4 address, IPv6 address, Mail server, etc...) set it up so that the greyed value uses the currently used field instead of the example (e.g. in A record, in ipv4 field, instead of `192.0.0.1` example use the current ipv4).

### Features

- [ ] Add IP4_PROVIDER and IP6_PROVIDER as option in the setting.
- [ ] More IP lookup methods.
- [ ] Add UPDATE_CRON and UPDATE_ON_START automatic updates on a schedule and at startup setting.
- [ ] Deleting records on shutdown or when no address is found setting.
- [ ] Detection groups (different domains with different providers).
- [ ] Proxy status per domain setting (right now it only accepts true or false for every domain).
- [ ] Implement WAF_LISTS, WAF IP lists.
- [ ] Add notifications and heartbeats (SHOUTRRR, HEALTHCHECKS, UPTIMEKUMA).
- [x] Implement Passkey registration, passwordless authentication and credential management.
- [ ] Make proxy enabled by default during the creation of a record.
- [ ] Let the user use `@` as domain on every field.
- [ ] Implement that not filling a field will use the default unless filling is absolutely necessary (e.g. in A record, in ipv4 field, the grayed current ipv4 will be used to fill the form if nothing specified from the user otherwise).

## Later

### UI

- [ ] Move the card footer at the bottom of the card.
- [ ] Fix the cards and list UI shifting when selecting the first record (still to be decided how).
- [ ] Give proper spacing for the `Proxy cannot be changed...` warning message from the Proxy status selector and make it the proper color (warning color not red error). What's `(TXT)` in the message? xd
- [ ] Fix the List and Cards selector shifting in the UI because of Columns button changing into order selector and vice versa.
- [ ] Make the add record popup appear from the `+ add record` button in human interface style.
- [ ] Move the import and export buttons (still to be decided where).
- [ ] Make the proxied color the proper one in white mode.
- [ ] Correct the animation of the side panel (the icons should stay still).
- [ ] Fix the topbar and sidebar-brand having different height.
- [ ] Fix the theme animation change flashing on change.

### Features

- [ ] Retire legacy backup codes.
- [ ] Create a compiled package for `docker-compose.yml`.
- [ ] Populate the Wiki on GitHub.
- [ ] Add more languages (UK, German, Russian, Indian, French, Chinese, Italian)
- [ ] Implement OIDC.
- [ ] Implement admin panel.
- [ ] Implement multi-account support.
