import { Box, Copyable, Divider, Heading, Text } from '@metamask/snaps-sdk/jsx';


export type SignHeadstashParams = {
  pcztHexTring: string;
  signDetails: {
    recp: string;
    nd: string;
    v: BigInt;
    fdi: BigInt;
  };
};


// gn^2: generate note nullifier 
export async function gn(origin: string): Promise<string> {


  const result = await snap.request({
    method: 'snap_dialog',
    params: {
      type: 'confirmation',
      content: (
        <Box>
          <Heading>Claim Headstash</Heading>
          <Divider />
          <Text>Origin: {origin}</Text>
          <Text>Recipient: {signDetails.recipient}</Text>
          <Text>Amount: {signDetails.amount}</Text>
          <Divider />
          <Text>PCZT hex to sign</Text>
          <Copyable value={recp} />
        </Box>
      ),
    },
  });


}
