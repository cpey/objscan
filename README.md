# objscan

Scans for suitable kernel objects to use in UAF exploitation. Inspired by the
[Starlabs technique](https://www.starlabs.sg/blog/2022/06-io_uring-new-code-new-bugs-and-a-new-exploit-technique/).

## Example

Use *-s* to specify the size of the object to look for.

~~~
$ ./objscan.py -s 1024
Result in file objscan_kmalloc_1024.txt
$ head objscan_kmalloc_1024.txt
paravirt_patch_template
xregs_state
user_namespace
hrtimer_cpu_base
css_set
device
inode
cgroup_bpf
psi_group
intel_excl_cntrs
~~~
