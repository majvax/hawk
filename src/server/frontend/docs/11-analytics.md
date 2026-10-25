# Analytics

A machine's **Analytics** and **Processes** tabs show its health: what
it's busy with, how full it is, and what's running. They work without
watching the screen.

## What's measured

| | |
|---|---|
| **CPU** | Total load, and each logical processor's |
| **Memory** | In use, of the total; committed memory, of its limit |
| **GPU** | Each graphics card's load (its busiest engine, as Task Manager shows it) and dedicated memory |
| **Network** | Received and sent, all adapters together, and which adapters are up |
| **Disks** | Read and write throughput, and each drive's space |
| **Temperatures** | The CPU's and each graphics card's, where the machine can read them |
| **Processes** | Every process: name, PID, user, CPU, memory, threads |

GPU numbers come from Windows' own counters, so they work with any
graphics card and no vendor software.

## Temperatures

Shown where the machine has a sensor Windows can read without extra
software, and as *unavailable* otherwise:

- **CPU**: the hottest of the machine's ACPI thermal zones, the sensor
  Windows reads for its own cooling. On many laptops it follows the CPU;
  on some PCs it's the board's, and many desktops have none at all. A zone
  reading under 20 °C, or one that hasn't moved at all in ten minutes, is
  taken for the fixed number some PCs report instead and shown as
  *unavailable*. The package temperature a tool like HWiNFO shows needs a
  kernel driver, which Hawk doesn't install.
- **Graphics cards**: what Task Manager shows, from the graphics driver
  (Windows 10 1803 and later), for any vendor. For an NVIDIA card whose
  driver doesn't give it there, from NVIDIA's own library, if the driver
  installed it.

Temperatures are in the live numbers only, not in the history. A machine
older than this dashboard sends none.

## Time ranges

**Live** shows the last five minutes, updated every second. **1 h**,
**24 h** and **7 d** show the machine's history, averaged into a few
hundred points; ranges longer than the machine keeps
([`history_days`](/docs/machine-config#metrics)) aren't offered. Gaps are
times the machine was off.

Above the charts, **sparklines** show each number over the last few
minutes, CPU and memory again in the machine list. Your browser keeps
them, for the machines you've watched since the page opened; hovering or a
screen reader gives the current, lowest and highest values.

## Ending a process

In the **Processes** tab, **End** stops a process, as Task Manager's
**End task** does: anything unsaved in it is lost. It asks you first,
naming the process and its PID.

- **Who:** the owner, and shares with control or shell access (with
  analytics, to see the list). It needs a fresh code from your
  authenticator, as power actions do; the relay won't pass it on
  otherwise, and the machine checks the role again.
- **What:** a shared account ends only what the signed-in user could end
  in Task Manager. The owner can end processes of any account, services
  included.
- **Never:** Windows' own (System, `csrss`, `wininit`, `smss`, `lsass`,
  `services`, `winlogon`, `svchost`, `dwm`, `fontdrvhost` and the like:
  ending a service host can make Windows restart), anything Windows marks critical or
  protects, and Hawk's own service and capture helper: ending those would
  stop the machine or cut you off. The machine says why it refused.
- **The right one:** the machine finds it by PID and the time it started,
  so a process that ended and whose PID went to a new one is never the one
  stopped.

Each one is in the [activity log](/docs/accounts#activity), as **Ended a
process**. The relay can't see which process: the request is end-to-end
encrypted like the rest.

## Alerts

**Alerts** at the top of a machine's page warns you when it's busy, full,
hot or gone:

- **CPU** over a percentage for a number of seconds;
- **Memory** over a percentage;
- **A drive's free space** under a percentage;
- **Temperature** (CPU or any graphics card) over a number of degrees;
- **Offline** for a number of seconds.

What fires shows as a badge on the machine and a short message in the
corner, and with **Also as browser notifications** ticked (your browser
asks once), as a notification. An alert clears once the number is back
past the line by a margin (10 points of CPU, 5 of memory, 2 of free space,
5 °C) for 10 seconds, so a number hovering at the line doesn't keep
warning. Near the ends of the scale the margin stops at 0% or 100%: CPU
over 1% clears at 0%, free space under 99% at 100% free.

Alerts are checked **by your browser, while the dashboard is open**: the
numbers are end-to-end encrypted, so the relay can't watch them for you.
CPU, memory, disk and temperature are checked while you're connected to
the machine; offline, for every machine in your list. They're kept in this
browser, per machine, not on the machine or the relay: each person sets
their own.

## Privacy

The machine samples itself and keeps the history on its own disk. When you
open the tab, your browser asks the machine for it over the same
end-to-end encrypted session as the screen: the relay passes it on without
being able to read it, and stores none of it.

## Who can see it

- **The owner**, always.
- **A shared account**, only if you ticked **Analytics** when sharing (see
  [Sharing](/docs/sharing)). The machine checks your signature on that, so
  the relay can't grant it.
- Nobody, with `enabled = false` in the machine's
  [config file](/docs/machine-config#metrics).

The process list shows what's running on the machine, which says a lot
about what someone is doing on it: share it with that in mind.
