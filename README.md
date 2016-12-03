# tcp-windows

Run `sudo zmap -p 443 -o - -B 10M | zgrab --port 443 --tls --http="/" > /dev/null`
and `./window.py > tcp-windows.out` at the same time.

Then run `./go.sh` and see cdf.pdf.


