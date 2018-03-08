# Usage: python gen_test_file.py
# Then, make sure the server has the same bytestring as below in the list of patterns to match

filename = 'intrusion.dat'

file = open(filename, 'wb')

file.write(b'\xff\xff\xff\xff')
file.close()