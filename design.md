Main Design Proposal:

## Memory Structure
```
// Our flow structure
type FlowData struct {
    flow Flow // provided by GoPacket
    flags uint8 // use one of the 8 flags to mark an occurred event
}

// Our hashmap
var flows := make(map[uint64]FlowData)
```
## Events

### Storing occurred events using Flags
For each distinct event that we see in a flow, we can set a flag on a specific bit.

| Bit 0  | Bit 1 | Bit 2 | Bit 3 | Bit 4 | Bit 5 | Bit 6 | Bit 7
| -- | -- |-- | -- | -- | -- |-- | -- |
| SYN seen | SYN-ACK seen | PUSH seen | first RST seen | second RST seen | third RST seen | | |

## Measurement

Upon detection of censorship, what should we gather?

## Optimizations

## BPFFilter
Filtering packets that are useful to us:
- TCP

### Threads (if possible)

We can have a pool of threads (workpool) which are waiting to process packets. There is also a queue where the packets not yet assigned to a thread for processing will be placed (when all threads are busy with other packets). If the queue becomes full, we will have no choice but to discard the new packets (which may be a good thing in case there is some sort of denial of service attack). Furthermore, the performance of the application can be measured by looking at the load on the queue.

### GoPacket Decoding

#### Lazy Decoding (not concurrent-safe): 
> gopacket optionally decodes packet data lazily, meaning it only decodes a packet layer when it needs to handle a function call
- It is not concurrent safe but that shouldn't be an issue because each packet can be handled in its own thread.

#### NoCopy Decoding (maybe)

> By default, gopacket will copy the slice passed to NewPacket and store the copy within the packet, so future mutations to the bytes underlying the slice don't affect the packet and its layers. If you can guarantee that the underlying slice bytes won't be changed, you can use NoCopy to tell gopacket.NewPacket, and it'll use the passed-in slice itself.
- This is may be good if we are not modifying the packet; however, it looks like (not tested) that using gopacket layers modifies the packet.
> Since layers have not all been decoded, each call to Layer() or Layers() has the potential to mutate the packet in order to decode the next layer. If a packet is used in multiple goroutines concurrently, don't use gopacket.Lazy. Then gopacket will decode the packet fully, and all future function calls won't mutate the object.
- However, [here](https://github.com/google/gopacket/blob/master/layers/decode_test.go), it shows code that uses both Lazy and NoCopy. Testing is required.

#### Another option for decoding is [DecodingLayerParser](https://godoc.org/github.com/google/gopacket#hdr-Fast_Decoding_With_DecodingLayerParser)

> TLDR: DecodingLayerParser takes about 10% of the time as NewPacket to decode packet data, but only for known packet stacks.
- It will only parse Eth, IPv4, IPv6, and TCP which may be what we only need.

### Flows

#### GoPacket has built in capability of determining a flow and endpoints

Looks like on each? non-application layer we can call some function with the word Flow in it to get a "src" and "dst". This would be useful for `NetworkLayer()` to get IP SRC and IP DST and `TransportLayer()` to get SRC PORT, and DST PORT.

### Lookup

For lookup optimization, it looks like a hash table would be the best data structure as we can lookup in constant time O(1). 

#### GoPacket FastHash()

GoPacket provides us with a quick (non-cryptographically secure) hashing function on the flow which is guaranteed to collide on the reverse flow (A->B and B->A produce the same output) which is incredibly advantageous.

### IP Fragmentation (Low Priority but may be important later on)

IP Fragmentation may be an issue where the TCP layer is split between two packets? GoPacket seems to have the ability to detect fragments and perform certain actions on them

## Documentation
Go documentation:
- Data Types: https://www.callicoder.com/golang-basic-types-operators-type-conversion/
- Structs: https://medium.com/rungo/structures-in-go-76377cc106a2
- GoPacket: https://godoc.org/github.com/google/gopacket
- PFring: https://godoc.org/github.com/google/gopacket/pfring
- Workpool: https://www.ardanlabs.com/blog/2013/05/thread-pooling-in-go-programming.html

## Questions

What is Cloudflare's privacy policy?
- I am assuming it is in their right to inspect the Network Layer and (potentially) the Transport Layer. However, what about the Application Layer?
