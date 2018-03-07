import pickle
import os.path
import sys


class IDS:
    def __init__(self):

        self.pattern_filename = 'intrusion_patterns.dat'

        self.patterns = self.load_patterns()

        cmd = 'a'
        while cmd != '':
            cmd = input(
                'Type \'a\' to add a new pattern, \'v\' to view the current patterns, or press <enter> to proceed: ')

            if cmd == 'a':

                # Read in a new pattern id, pattern
                pattern_id = input('Enter pattern id (int or str): ')

                try:
                    byte_pattern = bytes.fromhex(input('Enter pattern in hex: (ex. efa7e779...): '))
                except ValueError:
                    sys.stderr.write('Bad input. Are you sure you entered valid hex?\n')
                    continue

                # Add and save the pattern
                self.add_pattern(pattern_id, byte_pattern)

            elif cmd == 'v':

                print('id\tpattern')
                for pattern_id, pattern in self.patterns.items():
                    print('{}\t{}'.format(pattern_id, pattern))

            elif cmd != '':
                sys.stderr.write('Bad input.')

    def inspect_message(self, message):
        # Check if each pattern is in the message
        for pattern_id, pattern in self.patterns.items():
            if pattern in message:
                print('!!!INTRUSION DETECTED!!!')
                return True  # TODO Implement log

        return False

    def add_pattern(self, pattern_id, pattern):

        # Only maintain 50 patterns
        if len(self.patterns) <= 50:

            # Add the pattern, id to the dictionary
            self.patterns[pattern_id] = pattern

            # Save the new patterns dictionary to the pickle file
            pickle.dump(self.patterns, open(self.pattern_filename, 'wb'))

            print('Added pattern.')

        else:
            sys.stderr.write('Could not write pattern. 50 patterns already saved.')

    def load_patterns(self):
        # If there is no pattern file, create one and return an empty dict
        if not os.path.isfile(self.pattern_filename):
            pickle.dump({}, open(self.pattern_filename, 'wb'))
            return {}

        # Load and return the pattern dictionary from a saved pickle
        return pickle.load(open(self.pattern_filename, 'rb'))