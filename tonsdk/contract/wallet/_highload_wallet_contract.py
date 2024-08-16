import time
import decimal

from .. import Contract
from ._wallet_contract import WalletContract
from ...boc import Cell, begin_cell, begin_dict
from ...utils import Address, sign_message


class HighloadWalletContractBase(WalletContract):
    def create_data_cell(self):
        return begin_cell() \
            .store_uint(self.options["wallet_id"], 32) \
            .store_uint(0, 64) \
            .store_bytes(self.options["public_key"]) \
            .store_maybe_ref(None) \
            .end_cell()

    def create_signing_message(self, query_id: int=0):
        message = begin_cell().store_uint(self.options["wallet_id"], 32)
        return message.store_uint(query_id, 64)


class HighloadWalletV2Contract(HighloadWalletContractBase):
    def __init__(self, **kwargs) -> None:
        # https://github.com/akifoq/highload-wallet/blob/master/highload-wallet-v2-code.fc
        self.code = "B5EE9C720101090100E5000114FF00F4A413F4BCF2C80B010201200203020148040501EAF28308D71820D31FD33FF823AA1F5320B9F263ED44D0D31FD33FD3FFF404D153608040F40E6FA131F2605173BAF2A207F901541087F910F2A302F404D1F8007F8E16218010F4786FA5209802D307D43001FB009132E201B3E65B8325A1C840348040F4438AE63101C8CB1F13CB3FCBFFF400C9ED54080004D03002012006070017BD9CE76A26869AF98EB85FFC0041BE5F976A268698F98E99FE9FF98FA0268A91040207A0737D098C92DBFC95DD1F140034208040F4966FA56C122094305303B9DE2093333601926C21E2B3"
        kwargs["code"] = Cell.one_from_boc(self.code)
        super().__init__(**kwargs)
        if "wallet_id" not in kwargs:
            self.options["wallet_id"] = 698983191 + self.options["wc"]

    def create_transfer_message(self, recipients_list: list, query_id: int, timeout=60, dummy_signature=False):
        if query_id < int(time.time() + timeout) << 32:
            query_id = int(time.time() + timeout) << 32 + query_id

        signing_message = self.create_signing_message(query_id)
        recipients = begin_dict(16)
        for i, recipient in enumerate(recipients_list):
            payload_cell = Cell()
            if recipient.get('payload'):
                if type(recipient['payload']) == str:
                    if len(recipient['payload']) > 0:
                        payload_cell.bits.write_uint(0, 32)
                        payload_cell.bits.write_string(recipient['payload'])
                elif hasattr(recipient['payload'], 'refs'):
                    payload_cell = recipient['payload']
                else:
                    payload_cell.bits.write_bytes(recipient['payload'])

            order_header = Contract.create_internal_message_header(
                Address(recipient['address']), decimal.Decimal(recipient['amount'])
            )
            order = Contract.create_common_msg_info(
                order_header, recipient.get('state_init'), payload_cell
            )
            recipients.store_cell(
                i, begin_cell() \
                    .store_uint8(recipient.get('send_mode', 0)) \
                    .store_ref(order).end_cell()
            )

        signing_message.store_maybe_ref(recipients.end_cell())
        return self.create_external_message(
            signing_message.end_cell(), dummy_signature
        )

    def create_external_message(self, signing_message, dummy_signature=False):
        signature = bytes(64) if dummy_signature else sign_message(
            bytes(signing_message.bytes_hash()), self.options['private_key']).signature

        body = Cell()
        body.bits.write_bytes(signature)
        body.write_cell(signing_message)

        state_init = code = data = None
        self_address = self.address
        header = Contract.create_external_message_header(self_address)
        result_message = Contract.create_common_msg_info(
            header, state_init, body)

        return {
            "address": self_address,
            "message": result_message,
            "body": body,
            "signature": signature,
            "signing_message": signing_message,
            "state_init": state_init,
            "code": code,
            "data": data,
            "query_id": int.from_bytes(signing_message.bits.array[4:12], 'big')
        }

    def create_init_external_message(self, timeout=60):
        create_state_init = self.create_state_init()
        state_init = create_state_init["state_init"]
        address = create_state_init["address"]
        code = create_state_init["code"]
        data = create_state_init["data"]

        signing_message = self.create_signing_message(int(time.time() + timeout) << 32) \
            .store_maybe_ref(None).end_cell()
        signature = sign_message(
            bytes(signing_message.bytes_hash()), self.options['private_key']).signature

        body = Cell()
        body.bits.write_bytes(signature)
        body.write_cell(signing_message)

        header = Contract.create_external_message_header(address)
        external_message = Contract.create_common_msg_info(
            header, state_init, body)

        return {
            "address": address,
            "message": external_message,

            "body": body,
            "signing_message": signing_message,
            "state_init": state_init,
            "code": code,
            "data": data,
        }


class HighloadWalletV3Contract(HighloadWalletContractBase):
    def __init__(self, **kwargs) -> None:
        # Highload wallet V3
        self.code = "B5EE9C7241021001000228000114FF00F4A413F4BCF2C80B01020120020D02014803040078D020D74BC00101C060B0915BE101D0D3030171B0915BE0FA4030F828C705B39130E0D31F018210AE42E5A4BA9D8040D721D74CF82A01ED55FB04E030020120050A02027306070011ADCE76A2686B85FFC00201200809001AABB6ED44D0810122D721D70B3F0018AA3BED44D08307D721D70B1F0201200B0C001BB9A6EED44D0810162D721D70B15800E5B8BF2EDA2EDFB21AB09028409B0ED44D0810120D721F404F404D33FD315D1058E1BF82325A15210B99F326DF82305AA0015A112B992306DDE923033E2923033E25230800DF40F6FA19ED021D721D70A00955F037FDB31E09130E259800DF40F6FA19CD001D721D70A00937FDB31E0915BE270801F6F2D48308D718D121F900ED44D0D3FFD31FF404F404D33FD315D1F82321A15220B98E12336DF82324AA00A112B9926D32DE58F82301DE541675F910F2A106D0D31FD4D307D30CD309D33FD315D15168BAF2A2515ABAF2A6F8232AA15250BCF2A304F823BBF2A35304800DF40F6FA199D024D721D70A00F2649130E20E01FE5309800DF40F6FA18E13D05004D718D20001F264C858CF16CF8301CF168E1030C824CF40CF8384095005A1A514CF40E2F800C94039800DF41704C8CBFF13CB1FF40012F40012CB3F12CB15C9ED54F80F21D0D30001F265D3020171B0925F03E0FA4001D70B01C000F2A5FA4031FA0031F401FA0031FA00318060D721D300010F0020F265D2000193D431D19130E272B1FB00B585BF03"
        kwargs["code"] = Cell.one_from_boc(self.code)
        super().__init__(**kwargs)
        if "wallet_id" not in kwargs:
            self.options["wallet_id"] = 698983191 + self.options["wc"]

    def create_transfer_message(self, recipients_list: list, query_id: int, timeout=60, dummy_signature=False):
        if query_id < int(time.time() + timeout) << 32:
            query_id = int(time.time() + timeout) << 32 + query_id

        signing_message = self.create_signing_message(query_id)
        recipients = begin_dict(16)
        for i, recipient in enumerate(recipients_list):
            payload_cell = Cell()
            if recipient.get('payload'):
                if type(recipient['payload']) == str:
                    if len(recipient['payload']) > 0:
                        payload_cell.bits.write_uint(0, 32)
                        payload_cell.bits.write_string(recipient['payload'])
                elif hasattr(recipient['payload'], 'refs'):
                    # payload_cell = recipient['payload']
                    pass
                else:
                    payload_cell.bits.write_bytes(recipient['payload'])

            order_header = Contract.create_internal_message_header(
                Address(recipient['address']), decimal.Decimal(recipient['amount'])
            )
            order = Contract.create_common_msg_info(
                order_header, recipient.get('state_init'), payload_cell
            )
            recipients.store_cell(
                i, begin_cell() \
                    .store_uint8(recipient.get('send_mode', 0)) \
                    .store_ref(order).end_cell()
            )

        signing_message.store_maybe_ref(recipients.end_cell())
        return self.create_external_message(
            signing_message.end_cell(), dummy_signature
        )

    def create_external_message(self, signing_message, dummy_signature=False):
        signature = bytes(64) if dummy_signature else sign_message(
            bytes(signing_message.bytes_hash()), self.options['private_key']).signature

        body = Cell()
        body.bits.write_bytes(signature)
        body.write_cell(signing_message)

        state_init = code = data = None
        self_address = self.address
        header = Contract.create_external_message_header(self_address)
        result_message = Contract.create_common_msg_info(
            header, state_init, body)

        return {
            "address": self_address,
            "message": result_message,
            "body": body,
            "signature": signature,
            "signing_message": signing_message,
            "state_init": state_init,
            "code": code,
            "data": data,
            "query_id": int.from_bytes(signing_message.bits.array[4:12], 'big')
        }

    def create_init_external_message(self, timeout=60):
        create_state_init = self.create_state_init()
        state_init = create_state_init["state_init"]
        address = create_state_init["address"]
        code = create_state_init["code"]
        data = create_state_init["data"]

        signing_message = self.create_signing_message(int(time.time() + timeout) << 32) \
            .store_maybe_ref(None).end_cell()
        signature = sign_message(
            bytes(signing_message.bytes_hash()), self.options['private_key']).signature

        body = Cell()
        body.bits.write_bytes(signature)
        body.write_cell(signing_message)

        header = Contract.create_external_message_header(address)
        external_message = Contract.create_common_msg_info(
            header, state_init, body)

        return {
            "address": address,
            "message": external_message,

            "body": body,
            "signing_message": signing_message,
            "state_init": state_init,
            "code": code,
            "data": data,
        }
