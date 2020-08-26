# Network Intrusion Dataset Generator
One of the most important things while writing ML model and training it, is the dataset used. And the quality and extensiveness of dataset determines the quality of your model & how well it will perform generally i.e. on new data. <br>
For years, KDD99 Dataset has been a benchmark of IDS model training & evaluations. But to fully customise your model as per your network server, and to train your model to handle anomalies in your network, it is important for it to know about your network traffic i.e. normal and anomalous traffic for each network is different.<br>
This `Network Intrusion Dataset Generator` lets you capture your network traffic using tcpdump and generates a csv file, that can readily be used for training your model. The best part is, it is fully customizable and one can choose to keep whatever features they want.

Code presented here is an implementation to generate csv file from packets captured on the network. One can also convert already captured packets in a pcap file to csv. The current implementation hasn't applied many filters on capturing of packets & can be extended according to one's own need. <br>
> This is a generalized implementation of the network intrustion dataset generator and further development will be done in future

### Getting Started
To clone the project in your local systems: 
```console
$ git clone https://github.com/piyush-palta/network-intrusion-dataset-generator.git
```

### Prerequisites
Make sure you have installed all of the following prerequisites on your development machine:
* Git - [Download & Install Git](https://git-scm.com/downloads). OSX and Linux machines typically have this already installed.
* Python3 - [Download & Install Python](https://www.python.org/downloads/). For linux machines, you can also use this [Python Docs](https://docs.python-guide.org/starting/install3/linux/) to install Python.
* pip3 - [Download & Install pip](https://pip.pypa.io/en/stable/installing/). Make sure you've installed python first.
* scapy - [Download & Install scapy](https://scapy.readthedocs.io/en/latest/installation.html). Make sure you install scapy with root priviledges. If you have installed pip you can use :
```bash
$ pip install --pre scapy[basic]
```
* tcpdump - [Download & Install tcpdump](https://scapy.readthedocs.io/en/latest/installation.html#platform-specific-instructions) 

> Note: 

### Installing
> Make sure to run the below commands as root user. If on debian distros, just add `sudo` with the commands
#### To use dataset generator in sniff mode :
> You can specify three arguments 
> * --time : Refers to the duration in seconds of sniffing. (Required)
> * --filter : You can set sniffing filters. To know more about what [filters](https://scapy.readthedocs.io/en/latest/usage.html) can be set. (Optional)
> * --csv : Path of the output csv (Optional)

```bash
$ python sniff.py --time=50
```
* To specify time and filter :

```bash
$ python sniff.py --time=50 --filter=tcp 
```

* To specify time and csv :

```bash
$ python sniff.py --time=50 --csv='/home/path/out.csv' 
```

#### To use dataset generator in pcap mode :
> You can specify two arguments 
> * --pcap : Path of the input pcap (Required)
> * --csv : Path of the output csv (Optional)

```bash
$ python pcap_to_csv.py --pcap='/sample.pcap'
```
* To specify csv path as well :

```bash
$ python pcap_to_csv.py --pcap='/sample.pcap' --csv='/home/path/out.csv' 
```

> Note : If `python` command doesn't work, try using `python3` 

### Future development Strategy
* The current implementation is more like a proof of concept & just a beginning of generalized dataset generator for Intrusion Detection Systems. Further development to cover up every aspect in detail i.e. configuring sniffing with filters etc will be taken up in the future.


### Contributions
* To know more about this project or contribute to it you can contact me [Piyush Palta](mailto:piyush.palta@outlook.com)

