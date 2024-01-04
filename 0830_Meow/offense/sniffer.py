import scapy.all as S
S.load_layer("http")
HTTPRequest
def filter_get_requests(pkg):
    return pkg.haslayer(HTTPRequest) and pkg[HTTPRequest].Method==b'GET'
S.sniff(lfilter=filter_get_requests) 