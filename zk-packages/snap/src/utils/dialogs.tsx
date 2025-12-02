import { Box, Heading, Text, Link } from '@metamask/snaps-sdk/jsx';

export const installDialog = async () => {
  await snap.request({
    method: 'snap_dialog',
    params: {
      type: 'alert',
      content: (
        <Box>
          <Heading>You have installed the Headstash Snap!</Heading>
          <Text>
            This snap powers the serialization of proof inputs and the actual proof generation of, involving your private key.\
            Please verify the headstash spec & also review the scripts we have for released package binary recreation & verification {' '}
            <Link href="https://headstash.terp.network/trustless/">
              https://headstash.terp.network/trustless
            </Link>
            .
          </Text>
        </Box>
      ),
    },
  });
};
