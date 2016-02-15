import base64
import gpgme
import os
import shutil
import tempfile
import unittest
import yaml
from encrypteddict import crypter, DecryptionError


class TestEncrypt(unittest.TestCase):
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

    def test_encrypt_with_no_dict_raises_exception(self):
        with self.assertRaises(TypeError):
            self.test_crypter.encrypt_all()

    def test_encrypt_with_unknown_key_raises_exception(self):
        with self.assertRaises(DecryptionError):
            a = self.test_crypter.encrypt_gpg('plain', ['notakey'])

    def test_encrypt_a_value(self):
        try:
            result = self.test_crypter.encrypt_gpg('plain', recipients=['4242B9C008039F75F7ADF7016B5C03D6CD7E05D1'])
        except Exception:
            self.fail('Encrypting a value should not raise an exception')

    def test_encrypt_a_value_returns_base64(self):
            result = self.test_crypter.encrypt_gpg('plain', recipients=['4242B9C008039F75F7ADF7016B5C03D6CD7E05D1'])
            try:
                base64.b64decode(result)
            except TypeError as e:
                self.fail('result is not base64 encoded')

    def test_encrypt_yaml_returns_valid_dict(self):
        result = self.test_crypter.encrypt_all({'simple_plain_number': 1, 'hash_of_hash': {'hash1': {'leaf1': 'DEC::(GPG)[thing1]!', 'leaf2': 'thing2'}, 'hash2': {'leaf1': 'thing1', 'leaf3': 'plain', 'leaf2': 'thing2'}}, 'multiline_5_lines': 'firstline\nsecondline\nthirdline\nforthline\nfithline\n', 'simple_plain_key': 'plain', 'simple_list': ['thing1', 'thing2', 'notencrypted'], 'simple_key': 'thing', 'hash_with_list': {'leaf1': ['thing1', 'thing2', 'plain']}, 'simple_hash': {'leaf1': 'thing1', 'leaf3': 'notencrypted', 'leaf2': 'thing2'}}, recipients=['4242B9C008039F75F7ADF7016B5C03D6CD7E05D1'])
        self.assertTrue('ENC' in str(result))
