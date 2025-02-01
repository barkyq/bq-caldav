# Personal CalDAV and CardDAV server

- a single WebDAV principal (at `"/"`)
- a single calendar-home-set (at `"/calendars/"`)
- a single addressbook-home-set (at `"/addressbook/"`)
- gzip compression of responses
- supports `expand` calendar-data requests

## Running

run the binary with the flag `-backend path/to/backend` to specify where the server will store the calendar and addressbook files.

## Backend

Currently the only backend implementation is `fsbackend` which transparently stores the resources in a directory structure:

```
backend/
├── calendars/
│   ├── example-calendar-collection/
│   │   ├── example-calendar-object.ics
│   │   └── props.xml
│   └── another-calendar-collection/
│       ├── another-calendar-object.ics
│       └── props.xml
└── addressbook/
    ├── example-vcard-object.vcf
    └── props.xml
```

Custom properties for the collections are stored in `props.xml` file, which is initialized by extended `MKCOL` or `MKCALENDAR` commands, and is updated by `PROPPATCH` command.

The `props.xml` file has the following document structure:

```text/xml
<?xml version="1.0" encoding="UTF-8"?>
<prop xmlns="DAV:">
  <calendar-free-busy-set xmlns="urn:ietf:params:xml:ns:caldav">
    <NO xmlns="urn:ietf:params:xml:ns:caldav"/>
  </calendar-free-busy-set>
  <supported-calendar-component-set xmlns="urn:ietf:params:xml:ns:caldav">
    <comp xmlns="urn:ietf:params:xml:ns:caldav" name="VEVENT"/>
  </supported-calendar-component-set>
  <displayname xmlns="DAV:">default</displayname>
  <calendar-order xmlns="http://apple.com/ns/ical/">1</calendar-order>
  <calendar-timezone xmlns="urn:ietf:params:xml:ns:caldav">BEGIN:VCALENDAR&#13;
CALSCALE:GREGORIAN&#13;
PRODID:-//Apple Inc.//iPhone OS 18.1.1//EN&#13;
VERSION:2.0&#13;
BEGIN:VTIMEZONE&#13;
TZID:Europe/Paris&#13;
BEGIN:DAYLIGHT&#13;
DTSTART:19810329T020000&#13;
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU&#13;
TZNAME:UTC+2&#13;
TZOFFSETFROM:+0100&#13;
TZOFFSETTO:+0200&#13;
END:DAYLIGHT&#13;
BEGIN:STANDARD&#13;
DTSTART:19961027T030000&#13;
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU&#13;
TZNAME:UTC+1&#13;
TZOFFSETFROM:+0200&#13;
TZOFFSETTO:+0100&#13;
END:STANDARD&#13;
END:VTIMEZONE&#13;
END:VCALENDAR&#13;
</calendar-timezone>
  <calendar-color xmlns="http://apple.com/ns/ical/">#479fd3</calendar-color>
</prop>
```

## Authorization

The server should be run behind a reverse-proxy which handles HTTPS, authorization basic, and .well-known redirection, such as nginx. Here is an example configuration block for nginx:

```conf
server {
	# SSL configuration

	listen 443 ssl http2;
	listen [::]:443 ssl http2;
	
	ssl_certificate /path/to/certificate.pem;
	ssl_certificate_key /path/to/certificate-key.pem;

	server_name caldav.example.com;

	location /.well-known/caldav {
		return 301 https://$host/;
	}

	location /.well-known/carddav {
		return 301 https://$host/;
	}
	
	location / {
		auth_basic "Authorization Required";
		auth_basic_user_file /etc/nginx/.passwd;
		proxy_pass http://127.0.0.1:8282/;
	}
}
```

## Compliance with RFC 4791 (caldav)

The implementation tries to be as compliant as is reasonable. There are some points where the server does not follow the RFC. Here is an incomplete list of failures of compliance

- Allows queries with filters whose start and end times are not contained between the `min-date-time` and `max-date-time` properties.

## Compliance with RFC 5455 (icalendar)

The server is strict about calendar objects it receives. Besides the requirements specified in RFC 5455 and RFC 4791, this implementation adopts the following rules:

- Calendar objects must have at exactly one toplevel non-timezone component without `RECURRENCE-ID` (the master component).
- Calendar objects cannot contain `VFREEBUSY` components.
- Components of type `VJOURNAL` cannot have `RRULE`, `RDATE`, `EXDATE`, or `RECURRENCE-ID` properties.
- Components of type `VEVENT` and `VTODO` cannot have the `RDATE` property (only `RRULE` and `EXDATE`).
- Components with `RECURRENCE-ID` set cannot have `RRULE`, `RDATE`, or `EXDATE` properties.
