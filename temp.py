import math

def mean(arr):
    n = len(arr)
    return sum(arr)/n

def stddev(arr):
    mn = mean(arr)
    return math.sqrt(sum((num - mn)**2 for num in arr)/len(arr))


def rto_estimate(arr):
    srtt = arr[0]
    rttvar = arr[0]/2
    beta = 0.25
    alpha = 0.125

    for i in range(1,len(arr)):
        rttvar = (1-beta) * rttvar + beta * abs(arr[i] - srtt)
        srtt = (1-alpha) * srtt + alpha * arr[i]

    return srtt,rttvar
        


arr = [80,100,90,150,200,95,120,300]
mu = mean(arr)
std = stddev(arr)
timeout_naive = (mu + 4 * std)
print(mu)
print(std)
print(timeout_naive)

print()

srtt, rttvar = rto_estimate(arr)
print(srtt)
print(rttvar)
print(srtt +  4 * rttvar)
print(srtt + 2*rttvar)

estimate02 = srtt + 2*rttvar
miss = 0
for i in arr:
    if (i - estimate02) > 0:
        miss+=1

print(miss/len(arr)  * 100)

print()






