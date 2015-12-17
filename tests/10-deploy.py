#!/usr/bin/env python3

import amulet
import requests
import unittest


seconds = 990
class TestDeployment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ''' Set up the deployment in the class.'''
        cls.deployment = amulet.Deployment(series='trusty')

        cls.deployment.add('tls')

        try:
            cls.deployment.setup(timeout=seconds)
            cls.deployment.sentry.wait()
        except amulet.helpers.TimeoutError:
            msg='The environment did not set up in {0} seconds!'.format(seconds)
            amulet.raise_status(amulet.SKIP, msg=msg)
        except:
            raise


    def test_leader(self):
        unit_0 = self.deployment.sentry['tls'][0]
        # With only one unit the first unit should be leader.
        output, exit_code = unit_0.run('is_leader')
        assert(exit_code == 0, 'The first unit was not the leader!')
        self.leader_unit = unit_0



    def test_add_units(self):
        # Now you can use self.deployment.sentry.unit[UNIT] to address each of
        # the units and perform more in-depth steps.  You can also reference
        # the first unit as self.unit.
        # There are three test statuses that can be triggered with
        # amulet.raise_status():
        #   - amulet.PASS
        #   - amulet.FAIL
        #   - amulet.SKIP
        # Each unit has the following methods:
        #   - .info - An array of the information of that unit from Juju
        #   - .file(PATH) - Get the details of a file on that unit
        #   - .file_contents(PATH) - Get plain text output of PATH file from that unit
        #   - .directory(PATH) - Get details of directory
        #   - .directory_contents(PATH) - List files and folders in PATH on that unit
        #   - .relation(relation, service:rel) - Get relation data from return service
        #          add tests here to confirm service is up and working properly
        # For example, to confirm that it has a functioning HTTP server:
        #     page = requests.get('http://{}'.format(self.unit.info['public-address']))
        #     page.raise_for_status()
        # More information on writing Amulet tests can be found at:
        #     https://jujucharms.com/docs/stable/tools-amulet
        pass


if __name__ == '__main__':
    unittest.main()
