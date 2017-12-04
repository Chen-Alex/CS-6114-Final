with open('instructions.txt') as f:
    for line in f:
        words = line.split(" ")
        words = [word.strip() for word in words]
        print words[0]
        print words[1]
        print words[2]
        print words[3]
        print 'end of line'
