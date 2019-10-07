from xdp_filters import IP_Filter
import time

filter = IP_Filter(attackkey="955a5cd15843aa5c4155fd3f69651e15")

filter.attach()
time.sleep(5)
#filter.remove()
filter.remove()

filter.attackkey = "a877a80fc3e21a6f001c4d2f514ed993"

filter.attach()
time.sleep(5)
filter.remove()