#!/usr/bin/python

# Import this for the generic dbus code
import dbus
# Import this to enable the MainLoop code. Without this import the
# script will appear to work, except that the MainLoop never actually
# runs, so no events are received.
import dbus.glib
# Import this for the definition of the MainLoop stuff.
import gobject

# The handler function for a signal. This function is trigger whenever
# a signal is received. The argument of the function is the paylod of
# the signal, in this case only a message string.
def my_events_handler(message):
        print "GTKG says '" + message + "'"

def download_done_handler(message):
        print "GTKG says that '" + message + "' has been downloaded."

def peermode_change_handler(message):
        print "GTKG switched to peermode " + message + "."

# Get access to the session bus.
bus = dbus.Bus(dbus.Bus.TYPE_SESSION)

# Attach the handler function as a callback to the bus. To keep things
# simple this handler listens to all signals emitted by the
# net.gtkg.Events interface.
bus.add_signal_receiver(my_events_handler,
                        'Events',           # Signal name
                        'net.gtkg.Events',  # Interface
                        None,               # Named service
                        None                # Path
                        )

# Attach the handler for the DownloadDone signal.
bus.add_signal_receiver(download_done_handler,
                        'DownloadDone', 'net.gtkg.Events', None, None )

# Attach the handler for the PeermodeChange signal.
bus.add_signal_receiver(peermode_change_handler,
                        'PeermodeChange', 'net.gtkg.Events', None, None )

# Indicate readyness and start the main loop which will call the
# callback when the correct signal is received.
print "Listening for gtk-gnutella events"
loop = gobject.MainLoop()
loop.run()
