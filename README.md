#PyCAS

This was intended as  a python-only replacement for [the Go version](https://github.com/CenterForOpenScience/fakeCAS).
Running this script provides a fake Central Authentication Server for running [osf.io](https://github.com/CenterForOpenScience/osf.io) in development mode

## Running PyCAS

Run:
~~~ bash
python fakecas.py
~~~

There are additional options:

### Changing port

~~~ bash
python fakecas.py --port=9000
~~~

or 

~~~ bash
python fakecas.py -p 9000
~~~

### Changing Log file name

##Future updates

* Proper logging
* Program options
* Cleanup


## How to 