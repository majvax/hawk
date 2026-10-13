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
| **Processes** | Every process: name, PID, user, CPU, memory, threads |

GPU numbers come from Windows' own counters, so they work with any
graphics card and no vendor software.

## Time ranges

**Live** shows the last five minutes, updated every second. **1 h**,
**24 h** and **7 d** show the machine's history, averaged into a few
hundred points; ranges longer than the machine keeps
([`history_days`](/docs/machine-config#metrics)) aren't offered. Gaps are
times the machine was off.

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
