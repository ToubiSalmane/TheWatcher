import socket

def getLocalIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually send data, just gets the IP address of the interface used for this destination
        s.connect(('8.8.8.8', 80)) 
        ip = s.getsockname()[0]
    except socket.error:
        raise Exception('Unable to get the local IP@')
    finally:
        s.close()
    return ip