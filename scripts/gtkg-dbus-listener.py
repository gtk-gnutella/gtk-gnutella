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
def my_signal_handler(message):
        print "GTKG says '" + message + "'"

# Get access to the session bus.
bus = dbus.Bus(dbus.Bus.TYPE_SESSION)

# Attach the handler function as a callback to the bus. To keep things
# simple this handler listens to all signals emitted by the
# net.gtkg.Events interface.
bus.add_signal_receiver(my_signal_handler,
                        None,               # Signal name
                        'net.gtkg.Events',  # Interface
                        None,               # Named service
                        None                # Path
                        )

# Indicate readyness and start the main loop which will call the
# callback when the correct signal is received.
print "Listening for Gtk-Gnutella events"
loop = gobject.MainLoop()
loop.run()
