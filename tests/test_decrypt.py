import gpgme
import os
import shutil
import tempfile
import unittest
import yaml
from encrypteddict import crypter, DecryptionError, UnsupportedEncryptionMethod


class TestDecrypt(unittest.TestCase):
    gpg_conf_contents = ''
    import_keys = ['test_decrypt.asc']
    keydir = os.path.join(os.path.dirname(__file__), 'keys')
    ctx = None
        

    def keyfile(self, key):
        return open(os.path.join(self.keydir, key), 'rb')

    def setUp(self):
        self._gpghome = tempfile.mkdtemp(prefix='tmp.gpghome')
        os.environ['GNUPGHOME'] = self._gpghome
        with open(os.path.join(self._gpghome, 'gpg.conf'), 'wb') as fp:
            fp.write(self.gpg_conf_contents.encode('UTF-8'))
        # import requested keys into the keyring
        self.ctx = gpgme.Context()
        for key in self.import_keys:
            with self.keyfile(key) as fp:
                self.ctx.import_(fp)
        self.test_crypter = crypter(gpg_home=self._gpghome)

    def tearDown(self):
        del os.environ['GNUPGHOME']
        shutil.rmtree(self._gpghome, ignore_errors=True)

    def test_decrypt_with_no_dict_raises_exception(self):
        with self.assertRaises(TypeError):
            self.test_crypter.decrypt_all()

    def test_decrypt_with_unknown_key_raises_exception(self):
        with open('tests/static/unknown_key.yaml', 'r') as yaml_file:
            test_dict = yaml.load(yaml_file)
        with self.assertRaises(DecryptionError):
            self.test_crypter.decrypt_all(test_dict)

    def test_decrypt_a_value(self):
        self.assertEqual(self.test_crypter.decrypt_gpg('hQIMAyCeTdU57g8QAQ/9GoRLUllutEJR7avVaRilafGs+UnoDO9y/7p86H9PtRUXxsRzLgb7xHDstP7xNTXHh/eY/7eQbQGulhmJ1pTpq+F9Vwbr3R9XKXDiYvFTQq+NQPD/+9QzFYI8HjYVU2JEj1FOX/VFJ2rF9YPY7FKu6kBVUT0RFjZ7qSlQmDgzTUpBRTLGLy7Xm1u7AwYMFrERJB3GK/HbnTnzPTUdzxeztnmjMzAxcz+IjFrCosjxW9zioKJKAKO4F5g4k0/IIMTBsoeq2hZAaB1jRE+d+dL0eTOtGlxR5YggurIvCSt486jziDrM3qZM525CA1ApFf0MfCZItFBo7xknpvWxhjSOXh/QkiA8I7+A1MGMfeQOevfBZGQxKKtwDsjKYIpip+0KXATwlCR26chpx8X9pPjVizQJQLFKiz6Z1ULT9nUMKit76NMh91UDk6jUkryt0qQd70oX5XzgUMspjEKYmJk8OBLnV4ZAHTwkNkdvS2MaMUqR7OIbruJUQykMQMI6jDcEeQvyfrwTlSv8YUvj2GF9vm9wRljZsR3pSk898nK0QmCCq6yLUrBmE5VD6D5EJOCfeeTuku8tmzPA6cSRAMGK1aAnofQ0M3QjE6AMsit+kYnyrB06A+DTddzBLyL8MBZQadTcV8GvWa1AOkIbzTNC+41mfmF0AwyxjFSQOHK+pE7SQAHlVgmj5cYOJ1YSAgekv6aPxGYicCZ8XEwztBh4K+AAY08d6Bz/Fn68MmhqdCqWgmzqaOdCWkTm74jWuTB0nrk='),'thing')

    def test_decrypt_yaml_returns_valid_dict(self):
        with open('tests/static/test_decrypt.yaml', 'r') as yaml_file:
            test_dict = yaml.load(yaml_file)
        print(self.test_crypter.decrypt_all(test_dict))
        self.assertEqual(self.test_crypter.decrypt_all(test_dict),{'simple_plain_number': 1, 'hash_of_hash': {'hash1': {'leaf1': 'thing1', 'leaf2': 'thing2'}, 'hash2': {'leaf1': 'thing1', 'leaf3': 'plain', 'leaf2': 'thing2'}}, 'multiline_5_lines': 'firstline\nsecondline\nthirdline\nforthline\nfithline\n', 'simple_plain_key': 'plain', 'simple_list': ['thing1', 'thing2', 'notencrypted'], 'simple_key': 'thing', 'hash_with_list': {'leaf1': ['thing1', 'thing2', 'plain']}, 'simple_hash': {'leaf1': 'thing1', 'leaf3': 'notencrypted', 'leaf2': 'thing2'}})
