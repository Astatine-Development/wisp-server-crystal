# wisp-server-crystal
tldr: A janky wisp server port to crystal-lang, expect bugs.

Stability untested, only basic testing was done to see if it "works"
UDP support completely untested atm, some other things might be broken, not really sure.

## Known issues:

While it does work at making http requests, aka it would work fine for proxies for the most part, TCP streams are broken and UDP is completely untested.
  
> # `How to use?`

-------------------------------------------------------------------------------

> Install crystal (https://crystal-lang.org/install/)

> Clone this repo and cd into it

> For testing run `crystal run wisp.cr` if you make a program using it you can have a production compile with `crystal build wisp.cr --release --no-debug --progress -o wisp` (replace demo with your program)

> Defaults on port 3001
