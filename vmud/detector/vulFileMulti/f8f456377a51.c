









static int check_smb2_hdr(struct smb2_hdr *hdr)
{
	
	if (hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR)
		return 1;
	return 0;
}


static const __le16 smb2_req_struct_sizes[NUMBER_OF_SMB2_COMMANDS] = {
	 cpu_to_le16(36), cpu_to_le16(25), cpu_to_le16(4), cpu_to_le16(9), cpu_to_le16(4), cpu_to_le16(57), cpu_to_le16(24), cpu_to_le16(24), cpu_to_le16(49), cpu_to_le16(49), cpu_to_le16(48), cpu_to_le16(57), cpu_to_le16(4), cpu_to_le16(4), cpu_to_le16(33), cpu_to_le16(32), cpu_to_le16(41), cpu_to_le16(33),  cpu_to_le16(36)


















};


static const bool has_smb2_data_area[NUMBER_OF_SMB2_COMMANDS] = {
	 true, true, false, true, false, true, false, false, true, true, true, true, false, false, true, false, true, true, false };




















static int smb2_get_data_area_len(unsigned int *off, unsigned int *len, struct smb2_hdr *hdr)
{
	int ret = 0;

	*off = 0;
	*len = 0;

	
	if (hdr->Status && hdr->Status != STATUS_MORE_PROCESSING_REQUIRED && (((struct smb2_err_rsp *)hdr)->StructureSize) == SMB2_ERROR_STRUCTURE_SIZE2_LE)
		return ret;

	
	switch (hdr->Command) {
	case SMB2_SESSION_SETUP:
		*off = le16_to_cpu(((struct smb2_sess_setup_req *)hdr)->SecurityBufferOffset);
		*len = le16_to_cpu(((struct smb2_sess_setup_req *)hdr)->SecurityBufferLength);
		break;
	case SMB2_TREE_CONNECT:
		*off = le16_to_cpu(((struct smb2_tree_connect_req *)hdr)->PathOffset);
		*len = le16_to_cpu(((struct smb2_tree_connect_req *)hdr)->PathLength);
		break;
	case SMB2_CREATE:
	{
		if (((struct smb2_create_req *)hdr)->CreateContextsLength) {
			*off = le32_to_cpu(((struct smb2_create_req *)
				hdr)->CreateContextsOffset);
			*len = le32_to_cpu(((struct smb2_create_req *)
				hdr)->CreateContextsLength);
			break;
		}

		*off = le16_to_cpu(((struct smb2_create_req *)hdr)->NameOffset);
		*len = le16_to_cpu(((struct smb2_create_req *)hdr)->NameLength);
		break;
	}
	case SMB2_QUERY_INFO:
		*off = le16_to_cpu(((struct smb2_query_info_req *)hdr)->InputBufferOffset);
		*len = le32_to_cpu(((struct smb2_query_info_req *)hdr)->InputBufferLength);
		break;
	case SMB2_SET_INFO:
		*off = le16_to_cpu(((struct smb2_set_info_req *)hdr)->BufferOffset);
		*len = le32_to_cpu(((struct smb2_set_info_req *)hdr)->BufferLength);
		break;
	case SMB2_READ:
		*off = le16_to_cpu(((struct smb2_read_req *)hdr)->ReadChannelInfoOffset);
		*len = le16_to_cpu(((struct smb2_read_req *)hdr)->ReadChannelInfoLength);
		break;
	case SMB2_WRITE:
		if (((struct smb2_write_req *)hdr)->DataOffset) {
			*off = le16_to_cpu(((struct smb2_write_req *)hdr)->DataOffset);
			*len = le32_to_cpu(((struct smb2_write_req *)hdr)->Length);
			break;
		}

		*off = le16_to_cpu(((struct smb2_write_req *)hdr)->WriteChannelInfoOffset);
		*len = le16_to_cpu(((struct smb2_write_req *)hdr)->WriteChannelInfoLength);
		break;
	case SMB2_QUERY_DIRECTORY:
		*off = le16_to_cpu(((struct smb2_query_directory_req *)hdr)->FileNameOffset);
		*len = le16_to_cpu(((struct smb2_query_directory_req *)hdr)->FileNameLength);
		break;
	case SMB2_LOCK:
	{
		int lock_count;

		
		lock_count = le16_to_cpu(((struct smb2_lock_req *)hdr)->LockCount) - 1;
		if (lock_count > 0) {
			*off = __SMB2_HEADER_STRUCTURE_SIZE + 48;
			*len = sizeof(struct smb2_lock_element) * lock_count;
		}
		break;
	}
	case SMB2_IOCTL:
		*off = le32_to_cpu(((struct smb2_ioctl_req *)hdr)->InputOffset);
		*len = le32_to_cpu(((struct smb2_ioctl_req *)hdr)->InputCount);
		break;
	default:
		ksmbd_debug(SMB, "no length check for command\n");
		break;
	}

	if (*off > 4096) {
		ksmbd_debug(SMB, "offset %d too large\n", *off);
		ret = -EINVAL;
	} else if ((u64)*off + *len > MAX_STREAM_PROT_LEN) {
		ksmbd_debug(SMB, "Request is larger than maximum stream protocol length(%u): %llu\n", MAX_STREAM_PROT_LEN, (u64)*off + *len);
		ret = -EINVAL;
	}

	return ret;
}


static int smb2_calc_size(void *buf, unsigned int *len)
{
	struct smb2_pdu *pdu = (struct smb2_pdu *)buf;
	struct smb2_hdr *hdr = &pdu->hdr;
	unsigned int offset; 
	unsigned int data_length; 
	int ret;

	
	*len = le16_to_cpu(hdr->StructureSize);

	
	*len += le16_to_cpu(pdu->StructureSize2);
	
	if (hdr->Command == SMB2_LOCK)
		*len -= sizeof(struct smb2_lock_element);

	if (has_smb2_data_area[le16_to_cpu(hdr->Command)] == false)
		goto calc_size_exit;

	ret = smb2_get_data_area_len(&offset, &data_length, hdr);
	if (ret)
		return ret;
	ksmbd_debug(SMB, "SMB2 data length %u offset %u\n", data_length, offset);

	if (data_length > 0) {
		
		if (offset + 1 < *len) {
			ksmbd_debug(SMB, "data area offset %d overlaps SMB2 header %u\n", offset + 1, *len);

			return -EINVAL;
		}

		*len = offset + data_length;
	}

calc_size_exit:
	ksmbd_debug(SMB, "SMB2 len %u\n", *len);
	return 0;
}

static inline int smb2_query_info_req_len(struct smb2_query_info_req *h)
{
	return le32_to_cpu(h->InputBufferLength) + le32_to_cpu(h->OutputBufferLength);
}

static inline int smb2_set_info_req_len(struct smb2_set_info_req *h)
{
	return le32_to_cpu(h->BufferLength);
}

static inline int smb2_read_req_len(struct smb2_read_req *h)
{
	return le32_to_cpu(h->Length);
}

static inline int smb2_write_req_len(struct smb2_write_req *h)
{
	return le32_to_cpu(h->Length);
}

static inline int smb2_query_dir_req_len(struct smb2_query_directory_req *h)
{
	return le32_to_cpu(h->OutputBufferLength);
}

static inline int smb2_ioctl_req_len(struct smb2_ioctl_req *h)
{
	return le32_to_cpu(h->InputCount) + le32_to_cpu(h->OutputCount);
}

static inline int smb2_ioctl_resp_len(struct smb2_ioctl_req *h)
{
	return le32_to_cpu(h->MaxInputResponse) + le32_to_cpu(h->MaxOutputResponse);
}

static int smb2_validate_credit_charge(struct ksmbd_conn *conn, struct smb2_hdr *hdr)
{
	unsigned int req_len = 0, expect_resp_len = 0, calc_credit_num, max_len;
	unsigned short credit_charge = le16_to_cpu(hdr->CreditCharge);
	void *__hdr = hdr;
	int ret = 0;

	switch (hdr->Command) {
	case SMB2_QUERY_INFO:
		req_len = smb2_query_info_req_len(__hdr);
		break;
	case SMB2_SET_INFO:
		req_len = smb2_set_info_req_len(__hdr);
		break;
	case SMB2_READ:
		req_len = smb2_read_req_len(__hdr);
		break;
	case SMB2_WRITE:
		req_len = smb2_write_req_len(__hdr);
		break;
	case SMB2_QUERY_DIRECTORY:
		req_len = smb2_query_dir_req_len(__hdr);
		break;
	case SMB2_IOCTL:
		req_len = smb2_ioctl_req_len(__hdr);
		expect_resp_len = smb2_ioctl_resp_len(__hdr);
		break;
	case SMB2_CANCEL:
		return 0;
	default:
		req_len = 1;
		break;
	}

	credit_charge = max_t(unsigned short, credit_charge, 1);
	max_len = max_t(unsigned int, req_len, expect_resp_len);
	calc_credit_num = DIV_ROUND_UP(max_len, SMB2_MAX_BUFFER_SIZE);

	if (credit_charge < calc_credit_num) {
		ksmbd_debug(SMB, "Insufficient credit charge, given: %d, needed: %d\n", credit_charge, calc_credit_num);
		return 1;
	} else if (credit_charge > conn->vals->max_credits) {
		ksmbd_debug(SMB, "Too large credit charge: %d\n", credit_charge);
		return 1;
	}

	spin_lock(&conn->credits_lock);
	if (credit_charge > conn->total_credits) {
		ksmbd_debug(SMB, "Insufficient credits granted, given: %u, granted: %u\n", credit_charge, conn->total_credits);
		ret = 1;
	}

	if ((u64)conn->outstanding_credits + credit_charge > conn->total_credits) {
		ksmbd_debug(SMB, "Limits exceeding the maximum allowable outstanding requests, given : %u, pending : %u\n", credit_charge, conn->outstanding_credits);
		ret = 1;
	} else conn->outstanding_credits += credit_charge;

	spin_unlock(&conn->credits_lock);

	return ret;
}

int ksmbd_smb2_check_message(struct ksmbd_work *work)
{
	struct smb2_pdu *pdu = ksmbd_req_buf_next(work);
	struct smb2_hdr *hdr = &pdu->hdr;
	int command;
	__u32 clc_len;  
	__u32 len = get_rfc1002_len(work->request_buf);

	if (le32_to_cpu(hdr->NextCommand) > 0)
		len = le32_to_cpu(hdr->NextCommand);
	else if (work->next_smb2_rcv_hdr_off)
		len -= work->next_smb2_rcv_hdr_off;

	if (check_smb2_hdr(hdr))
		return 1;

	if (hdr->StructureSize != SMB2_HEADER_STRUCTURE_SIZE) {
		ksmbd_debug(SMB, "Illegal structure size %u\n", le16_to_cpu(hdr->StructureSize));
		return 1;
	}

	command = le16_to_cpu(hdr->Command);
	if (command >= NUMBER_OF_SMB2_COMMANDS) {
		ksmbd_debug(SMB, "Illegal SMB2 command %d\n", command);
		return 1;
	}

	if (smb2_req_struct_sizes[command] != pdu->StructureSize2) {
		if (command != SMB2_OPLOCK_BREAK_HE && (hdr->Status == 0 || pdu->StructureSize2 != SMB2_ERROR_STRUCTURE_SIZE2_LE)) {
			
			ksmbd_debug(SMB, "Illegal request size %u for command %d\n", le16_to_cpu(pdu->StructureSize2), command);

			return 1;
		} else if (command == SMB2_OPLOCK_BREAK_HE && hdr->Status == 0 && le16_to_cpu(pdu->StructureSize2) != OP_BREAK_STRUCT_SIZE_20 && le16_to_cpu(pdu->StructureSize2) != OP_BREAK_STRUCT_SIZE_21) {


			
			ksmbd_debug(SMB, "Illegal request size %d for oplock break\n", le16_to_cpu(pdu->StructureSize2));

			return 1;
		}
	}

	if (smb2_calc_size(hdr, &clc_len))
		return 1;

	if (len != clc_len) {
		
		if (clc_len == len + 1)
			goto validate_credit;

		
		if (ALIGN(clc_len, 8) == len)
			goto validate_credit;

		
		if (clc_len < len) {
			ksmbd_debug(SMB, "cli req padded more than expected. Length %d not %d for cmd:%d mid:%llu\n", len, clc_len, command, le64_to_cpu(hdr->MessageId));


			goto validate_credit;
		}

		ksmbd_debug(SMB, "cli req too short, len %d not %d. cmd:%d mid:%llu\n", len, clc_len, command, le64_to_cpu(hdr->MessageId));



		return 1;
	}

validate_credit:
	if ((work->conn->vals->capabilities & SMB2_GLOBAL_CAP_LARGE_MTU) && smb2_validate_credit_charge(work->conn, hdr)) {
		work->conn->ops->set_rsp_status(work, STATUS_INVALID_PARAMETER);
		return 1;
	}

	return 0;
}

int smb2_negotiate_request(struct ksmbd_work *work)
{
	return ksmbd_smb_negotiate_common(work, SMB2_NEGOTIATE_HE);
}
