
Section: V4V_Base

Role=None|Sender|Receiver|Connector|Listener
Protocol=Datagram|Stream
Async=False|True
ConnectOnly=False|True
PeerId=DOMID#|NONE
LocalPort=PORT#|NONE
RemotePort=PORT#|NONE
RingSize=<n>

Section: V4V_Data

Transfer=Internal|File
TransferFile=<path>
TransferTimeout=<ms>
TransmitSize=<n>
ReceiveSize=<n>
