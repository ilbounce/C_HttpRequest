# HttpRequest
Simple TLS functional for HTTPS requests in clear C implemented for Windows and Linux.

Linux compilation:
```console
gcc -o httprequest main.c request.c Map.c -lssl -lcrypto
```

Usage Example:
```C
#include <stdlib.h>
#include <stdio.h>

#include "request.h"
#include "Map.h"

void main()
{
	MAP* headers = create_map();
	map_set(headers, "Accept", "application/json");
	map_set(headers, "User-Agent", 
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36");

	MAP* data = create_map();
	map_set(data, "symbol", "BTCUSDT");

	const char* URI = "https://data.binance.com";
	
	RESPONSE* resp = httpRequest(URI, "/api/v3/ticker/price", "GET", headers, data);

	if (resp != NULL) {
		printf("%s\n", resp->content);
		free(resp->content);
		free(resp);
	}
}
```

```console
{"symbol":"BTCUSDT","price":"27802.67000000"}
```
