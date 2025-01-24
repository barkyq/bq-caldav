# simple personal caldav and carddav server

- supports a single WebDAV principal (at `"/"`)
- supports a single calendar-home-set (at `"/calendars/"`)
- supports a single addressbook-home-set (at `"/addressbook/"`)
- supports gzip compression of responses
- calendar collection supported-component-set contains only `VEVENT`

## running

run the binary with the flag `-backend path/to/backend` to specify where the server will store the calendar and addressbook files.

## backend

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
    <calendar-timezone xmlns="urn:ietf:params:xml:ns:caldav">
        BEGIN:VCALENDAR
        CALSCALE:GREGORIAN
        PRODID:-//Apple Inc.//iPhone OS 18.1.1//EN
        VERSION:2.0
        BEGIN:VTIMEZONE
        TZID:Europe/Paris
        BEGIN:DAYLIGHT
        DTSTART:19810329T020000
        RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU
        TZNAME:UTC+2
        TZOFFSETFROM:+0100
        TZOFFSETTO:+0200
        END:DAYLIGHT
        BEGIN:STANDARD
        DTSTART:19961027T030000
        RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU
        TZNAME:UTC+1
        TZOFFSETFROM:+0200
        TZOFFSETTO:+0100
        END:STANDARD
        END:VTIMEZONE
        END:VCALENDAR
    </calendar-timezone>
    <displayname xmlns="DAV:">default</displayname>
    <calendar-color xmlns="http://apple.com/ns/ical/">#44798e</calendar-color>
    <calendar-description xmlns="urn:ietf:params:xml:ns:caldav">default calendar</calendar-description>
    <calendar-order xmlns="http://apple.com/ns/ical/">1</calendar-order>
</prop>
```

## authorization

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
