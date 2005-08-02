#!/usr/bin/python

import dbus
import dbus.glib
import gobject

def my_signal_handler(message):
        print "GTKG says '" + message + "'"

bus = dbus.Bus(dbus.Bus.TYPE_SESSION)

print "Listening for Gtk-Gnutella events"
bus.add_signal_receiver(my_signal_handler,
                        None,
                        'net.gtkg.Events',
                        None,
                        None
                        )

loop = gobject.MainLoop()
loop.run()
