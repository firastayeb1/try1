
codecs = ['utf-8', 'utf-16', 'utf-32']


# Decode packet data
def decode_data(data):

    encoding = None

    for codec in codecs:

        try:
            content = data[:].decode(codec)
            print('Encoding: ' + codec + '\n\n' + str(content))
            encoding = codec
        except:
            continue

        if encoding is not None:
            break

    if encoding is None:
        print('\n---------- Encoding: Unknown ----------')
        try:
            print(data.decode('utf-8', 'ignore'))
        except:
            print('Nope')
            print(str(data))