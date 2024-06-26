


























PF_TYPE_DECL(WINAPI, HRESULT, SHCreateItemFromParsingName, (PCWSTR, IBindCtx*, REFIID, void **));
PF_TYPE_DECL(WINAPI, LPITEMIDLIST, SHSimpleIDListFromPath, (PCWSTR pszPath));





static HICON hMessageIcon = (HICON)INVALID_HANDLE_VALUE;
static char* szMessageText = NULL;
static char* szMessageTitle = NULL;
static char **szDialogItem;
static int nDialogItems;
static HWND hBrowseEdit;
extern HWND hUpdatesDlg;
static WNDPROC pOrgBrowseWndproc;
static const SETTEXTEX friggin_microsoft_unicode_amateurs = {ST_DEFAULT, CP_UTF8};
static BOOL notification_is_question;
static const notification_info* notification_more_info;
static BOOL settings_commcheck = FALSE;
static WNDPROC update_original_proc = NULL;
static HWINEVENTHOOK fp_weh = NULL;
static char *fp_title_str = "Microsoft Windows", *fp_button_str = "Format disk";

extern loc_cmd* selected_locale;


void SetDialogFocus(HWND hDlg, HWND hCtrl)
{
	SendMessage(hDlg, WM_NEXTDLGCTL, (WPARAM)hCtrl, TRUE);
}


INT CALLBACK BrowseDlgCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch(message) {
	case WM_DESTROY:
		GetWindowTextU(hBrowseEdit, szFolderPath, sizeof(szFolderPath));
		break;
	}
	return (INT)CallWindowProc(pOrgBrowseWndproc, hDlg, message, wParam, lParam);
}


INT CALLBACK BrowseInfoCallback(HWND hDlg, UINT message, LPARAM lParam, LPARAM pData)
{
	char dir[MAX_PATH];
	wchar_t* wpath;
	LPITEMIDLIST pidl;

	switch(message) {
	case BFFM_INITIALIZED:
		pOrgBrowseWndproc = (WNDPROC)SetWindowLongPtr(hDlg, GWLP_WNDPROC, (LONG_PTR)BrowseDlgCallback);
		
		
		hBrowseEdit = FindWindowExA(hDlg, NULL, "Edit", NULL);
		SetWindowTextU(hBrowseEdit, szFolderPath);
		SetDialogFocus(hDlg, hBrowseEdit);
		
		
		if (nWindowsVersion <= WINDOWS_XP) {
			SendMessageLU(hDlg, BFFM_SETSELECTION, (WPARAM)TRUE, szFolderPath);
		} else {
			
			wpath = utf8_to_wchar(szFolderPath);
			pidl = (*pfSHSimpleIDListFromPath)(wpath);
			safe_free(wpath);
			
			
			SendMessageW(hDlg, BFFM_SETSELECTION, (WPARAM)FALSE, (LPARAM)pidl);
			Sleep(100);
			PostMessageW(hDlg, BFFM_SETSELECTION, (WPARAM)FALSE, (LPARAM)pidl);
		}
		break;
	case BFFM_SELCHANGED:
		
		if (SHGetPathFromIDListU((LPITEMIDLIST)lParam, dir)) {
			SendMessageLU(hDlg, BFFM_SETSTATUSTEXT, 0, dir);
			SetWindowTextU(hBrowseEdit, dir);
		}
		break;
	}
	return 0;
}


void BrowseForFolder(void) {

	BROWSEINFOW bi;
	LPITEMIDLIST pidl;
	WCHAR *wpath;
	size_t i;
	HRESULT hr;
	IShellItem *psi = NULL;
	IShellItem *si_path = NULL;	
	IFileOpenDialog *pfod = NULL;
	WCHAR *fname;
	char* tmp_path = NULL;

	dialog_showing++;
	if (nWindowsVersion >= WINDOWS_VISTA) {
		INIT_VISTA_SHELL32;
		if (IS_VISTA_SHELL32_AVAILABLE) {
			hr = CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_INPROC, &IID_IFileOpenDialog, (LPVOID)&pfod);
			if (FAILED(hr)) {
				uprintf("CoCreateInstance for FileOpenDialog failed: error %X\n", hr);
				pfod = NULL;	
				goto fallback;
			}
			hr = pfod->lpVtbl->SetOptions(pfod, FOS_PICKFOLDERS);
			if (FAILED(hr)) {
				uprintf("Failed to set folder option for FileOpenDialog: error %X\n", hr);
				goto fallback;
			}
			
			wpath = utf8_to_wchar(szFolderPath);
			
			fname = NULL;
			if ((wpath != NULL) && (wcslen(wpath) >= 1)) {
				for (i = wcslen(wpath) - 1; i != 0; i--) {
					if (wpath[i] == L'\\') {
						wpath[i] = 0;
						fname = &wpath[i + 1];
						break;
					}
				}
			}

			hr = (*pfSHCreateItemFromParsingName)(wpath, NULL, &IID_IShellItem, (LPVOID)&si_path);
			if (SUCCEEDED(hr)) {
				if (wpath != NULL) {
					pfod->lpVtbl->SetFolder(pfod, si_path);
				}
				if (fname != NULL) {
					pfod->lpVtbl->SetFileName(pfod, fname);
				}
			}
			safe_free(wpath);

			hr = pfod->lpVtbl->Show(pfod, hMainDialog);
			if (SUCCEEDED(hr)) {
				hr = pfod->lpVtbl->GetResult(pfod, &psi);
				if (SUCCEEDED(hr)) {
					psi->lpVtbl->GetDisplayName(psi, SIGDN_FILESYSPATH, &wpath);
					tmp_path = wchar_to_utf8(wpath);
					CoTaskMemFree(wpath);
					if (tmp_path == NULL) {
						uprintf("Could not convert path\n");
					} else {
						static_strcpy(szFolderPath, tmp_path);
						safe_free(tmp_path);
					}
				} else {
					uprintf("Failed to set folder option for FileOpenDialog: error %X\n", hr);
				}
			} else if ((hr & 0xFFFF) != ERROR_CANCELLED) {
				
				uprintf("Could not show FileOpenDialog: error %X\n", hr);
				goto fallback;
			}
			pfod->lpVtbl->Release(pfod);
			dialog_showing--;
			return;
		}
fallback:
		if (pfod != NULL) {
			pfod->lpVtbl->Release(pfod);
		}
	}

	INIT_XP_SHELL32;
	memset(&bi, 0, sizeof(BROWSEINFOW));
	bi.hwndOwner = hMainDialog;
	bi.lpszTitle = utf8_to_wchar(lmprintf(MSG_106));
	bi.lpfn = BrowseInfoCallback;
	
	bi.ulFlags = BIF_RETURNFSANCESTORS | BIF_RETURNONLYFSDIRS | BIF_DONTGOBELOWDOMAIN | BIF_EDITBOX | 0x00000200;
	pidl = SHBrowseForFolderW(&bi);
	if (pidl != NULL) {
		CoTaskMemFree(pidl);
	}
	safe_free(bi.lpszTitle);
	dialog_showing--;
}


char* FileDialog(BOOL save, char* path, const ext_t* ext, DWORD options)
{
	DWORD tmp;
	OPENFILENAMEA ofn;
	char selected_name[MAX_PATH];
	char *ext_string = NULL, *all_files = NULL;
	size_t i, j, ext_strlen;
	BOOL r;
	char* filepath = NULL;
	HRESULT hr = FALSE;
	IFileDialog *pfd = NULL;
	IShellItem *psiResult;
	COMDLG_FILTERSPEC* filter_spec = NULL;
	wchar_t *wpath = NULL, *wfilename = NULL;
	IShellItem *si_path = NULL;	

	if ((ext == NULL) || (ext->count == 0) || (ext->extension == NULL) || (ext->description == NULL))
		return NULL;
	dialog_showing++;

	if (nWindowsVersion >= WINDOWS_VISTA) {
		INIT_VISTA_SHELL32;
		filter_spec = (COMDLG_FILTERSPEC*)calloc(ext->count + 1, sizeof(COMDLG_FILTERSPEC));
		if ((IS_VISTA_SHELL32_AVAILABLE) && (filter_spec != NULL)) {
			
			for (i = 0; i < ext->count; i++) {
				filter_spec[i].pszSpec = utf8_to_wchar(ext->extension[i]);
				filter_spec[i].pszName = utf8_to_wchar(ext->description[i]);
			}
			filter_spec[i].pszSpec = L"*.*";
			filter_spec[i].pszName = utf8_to_wchar(lmprintf(MSG_107));

			hr = CoCreateInstance(save ? &CLSID_FileSaveDialog : &CLSID_FileOpenDialog, NULL, CLSCTX_INPROC, &IID_IFileDialog, (LPVOID)&pfd);

			if (FAILED(hr)) {
				SetLastError(hr);
				uprintf("CoCreateInstance for FileOpenDialog failed: %s\n", WindowsErrorString());
				pfd = NULL;	
				goto fallback;
			}

			
			pfd->lpVtbl->SetFileTypes(pfd, (UINT)ext->count + 1, filter_spec);

			
			wpath = utf8_to_wchar(path);
			hr = (*pfSHCreateItemFromParsingName)(wpath, NULL, &IID_IShellItem, (LPVOID)&si_path);
			if (SUCCEEDED(hr)) {
				pfd->lpVtbl->SetFolder(pfd, si_path);
			}
			safe_free(wpath);

			
			wfilename = utf8_to_wchar((ext->filename == NULL) ? "" : ext->filename);
			if (wfilename != NULL) {
				pfd->lpVtbl->SetFileName(pfd, wfilename);
			}

			
			hr = pfd->lpVtbl->Show(pfd, hMainDialog);

			
			safe_free(wfilename);
			for (i = 0; i < ext->count; i++) {
				safe_free(filter_spec[i].pszSpec);
				safe_free(filter_spec[i].pszName);
			}
			safe_free(filter_spec[i].pszName);
			safe_free(filter_spec);

			if (SUCCEEDED(hr)) {
				
				hr = pfd->lpVtbl->GetResult(pfd, &psiResult);
				if (SUCCEEDED(hr)) {
					hr = psiResult->lpVtbl->GetDisplayName(psiResult, SIGDN_FILESYSPATH, &wpath);
					if (SUCCEEDED(hr)) {
						filepath = wchar_to_utf8(wpath);
						CoTaskMemFree(wpath);
					} else {
						SetLastError(hr);
						uprintf("Unable to access file path: %s\n", WindowsErrorString());
					}
					psiResult->lpVtbl->Release(psiResult);
				}
			} else if ((hr & 0xFFFF) != ERROR_CANCELLED) {
				
				SetLastError(hr);
				uprintf("Could not show FileOpenDialog: %s\n", WindowsErrorString());
				goto fallback;
			}
			pfd->lpVtbl->Release(pfd);
			dialog_showing--;
			return filepath;
		}
	fallback:
		safe_free(filter_spec);
		if (pfd != NULL) {
			pfd->lpVtbl->Release(pfd);
		}
	}

	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hMainDialog;
	
	static_sprintf(selected_name, "%s", (ext->filename == NULL)?"":ext->filename);
	ofn.lpstrFile = selected_name;
	ofn.nMaxFile = MAX_PATH;
	
	all_files = lmprintf(MSG_107);
	ext_strlen = 0;
	for (i=0; i<ext->count; i++) {
		ext_strlen += safe_strlen(ext->description[i]) + 2*safe_strlen(ext->extension[i]) + sizeof(" ()\r\r");
	}
	ext_strlen += safe_strlen(all_files) + sizeof(" (*.*)\r*.*\r");
	ext_string = (char*)malloc(ext_strlen+1);
	if (ext_string == NULL)
		return NULL;
	ext_string[0] = 0;
	for (i=0, j=0; i<ext->count; i++) {
		j += _snprintf(&ext_string[j], ext_strlen-j, "%s (%s)\r%s\r", ext->description[i], ext->extension[i], ext->extension[i]);
	}
	j = _snprintf(&ext_string[j], ext_strlen-j, "%s (*.*)\r*.*\r", all_files);
	
	for (i=0; i<ext_strlen; i++) {




		if (ext_string[i] == '\r') {



			ext_string[i] = 0;
		}
	}
	ofn.lpstrFilter = ext_string;
	ofn.nFilterIndex = 1;
	ofn.lpstrInitialDir = path;
	ofn.Flags = OFN_OVERWRITEPROMPT | options;
	
	if (save) {
		r = GetSaveFileNameU(&ofn);
	} else {
		r = GetOpenFileNameU(&ofn);
	}
	if (r) {
		filepath = safe_strdup(selected_name);
	} else {
		tmp = CommDlgExtendedError();
		if (tmp != 0) {
			uprintf("Could not select file for %s. Error %X\n", save?"save":"open", tmp);
		}
	}
	safe_free(ext_string);
	dialog_showing--;
	return filepath;
}


void CreateStatusBar(void)
{
	SIZE sz = {0, 0};
	RECT rect;
	LONG x, y, width, height;
	int edge[3];
	TBBUTTON tbbStatusToolbarButtons[1];
	TBBUTTONINFO tbi;
	HFONT hFont;
	HDC hDC;

	
	hStatus = CreateWindowExW(0, STATUSCLASSNAME, NULL, WS_CHILD | WS_VISIBLE | SBARS_TOOLTIPS | WS_CLIPSIBLINGS, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hMainDialog, (HMENU)IDC_STATUS, hMainInstance, NULL);


	
	GetClientRect(hStatus, &rect);
	height = rect.bottom;

	
	hFont = CreateFontA(-MulDiv(10, GetDeviceCaps(GetDC(hMainDialog), LOGPIXELSY), 72), 0, 0, 0, FW_MEDIUM, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, PROOF_QUALITY, 0, (nWindowsVersion >= WINDOWS_VISTA)?"Segoe UI":"Arial Unicode MS");


	
	hDC = GetDC(hMainDialog);
	SelectObject(hDC, hFont);
	GetTextExtentPoint32W(hDC, L"#", 1, &sz);
	if (hDC != NULL)
		ReleaseDC(hMainDialog, hDC);

	
	GetClientRect(hMainDialog, &rect);
	edge[1] = rect.right - (int)(SB_TIMER_SECTION_SIZE * fScale);
	edge[0] = edge[1] - (8 + sz.cx + 8 + 1); 
	edge[2] = rect.right;
	SendMessage(hStatus, SB_SETPARTS, (WPARAM)ARRAYSIZE(edge), (LPARAM)&edge);

	
	
	

	
	

	
	x = edge[0];
	if (nWindowsVersion <= WINDOWS_XP) {
		x -= 1;
		height -= 2;
	}
	y = rect.bottom - height + 1;
	width = edge[1] - edge[0] - 1;
	
	
	if ((fScale > 1.20f) && (fScale <2.40f))
		height -= 1;
	if (nWindowsVersion <= WINDOWS_7)
		height += 1;

	
	hStatusToolbar = CreateWindowExW(WS_EX_TRANSPARENT, TOOLBARCLASSNAME, NULL, WS_CHILD | WS_TABSTOP | WS_DISABLED | TBSTYLE_LIST | CCS_NOPARENTALIGN | CCS_NODIVIDER | CCS_NORESIZE, x, y, width, height, hMainDialog, (HMENU)IDC_STATUS_TOOLBAR, hMainInstance, NULL);


	
	SendMessage(hStatusToolbar, WM_SETFONT, (WPARAM)hFont, TRUE);
	SendMessage(hStatusToolbar, TB_SETEXTENDEDSTYLE, 0, (LPARAM)TBSTYLE_EX_MIXEDBUTTONS);
	SendMessage(hStatusToolbar, TB_SETIMAGELIST, 0, (LPARAM)NULL);
	SendMessage(hStatusToolbar, TB_SETDISABLEDIMAGELIST, 0, (LPARAM)NULL);
	SendMessage(hStatusToolbar, TB_SETBITMAPSIZE, 0, MAKELONG(0,0));

	
	memset(tbbStatusToolbarButtons, 0, sizeof(TBBUTTON));
	tbbStatusToolbarButtons[0].idCommand = IDC_HASH;
	tbbStatusToolbarButtons[0].fsStyle = BTNS_SHOWTEXT;
	tbbStatusToolbarButtons[0].fsState = TBSTATE_ENABLED;
	tbbStatusToolbarButtons[0].iString = (INT_PTR)L"#";
	SendMessage(hStatusToolbar, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);
	SendMessage(hStatusToolbar, TB_ADDBUTTONS, (WPARAM)1, (LPARAM)&tbbStatusToolbarButtons);

	SendMessage(hStatusToolbar, TB_SETBUTTONSIZE, 0, MAKELPARAM(width, height - 1));
	
	
	tbi.cbSize = sizeof(tbi);
	tbi.dwMask = TBIF_SIZE | TBIF_COMMAND;
	tbi.cx = (WORD)width;
	tbi.idCommand = IDC_HASH;
	SendMessage(hStatusToolbar, TB_SETBUTTONINFO, (WPARAM)IDC_HASH, (LPARAM)&tbi);

	
	
	SetWindowPos(hStatusToolbar, GetDlgItem(hMainDialog, IDCANCEL), x, y, width, height, 0);
	ShowWindow(hStatusToolbar, SW_SHOWNORMAL);
}


void CenterDialog(HWND hDlg)
{
	HWND hParent;
	RECT rc, rcDlg, rcParent;

	if ((hParent = GetParent(hDlg)) == NULL) {
		hParent = GetDesktopWindow();
	}

	GetWindowRect(hParent, &rcParent);
	GetWindowRect(hDlg, &rcDlg);
	CopyRect(&rc, &rcParent);

	
	
	
	OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top);
	OffsetRect(&rc, -rc.left, -rc.top);
	OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom);

	SetWindowPos(hDlg, HWND_TOP, rcParent.left + (rc.right / 2), rcParent.top + (rc.bottom / 2) - 25, 0, 0, SWP_NOSIZE);
}


SIZE GetBorderSize(HWND hDlg)
{
	RECT rect = {0, 0, 0, 0};
	SIZE size = {0, 0};
	WINDOWINFO wi;
	wi.cbSize = sizeof(WINDOWINFO);

	GetWindowInfo(hDlg, &wi);

	AdjustWindowRectEx(&rect, wi.dwStyle, FALSE, wi.dwExStyle);
	size.cx = rect.right - rect.left;
	size.cy = rect.bottom - rect.top;
	return size;
}

void ResizeMoveCtrl(HWND hDlg, HWND hCtrl, int dx, int dy, int dw, int dh, float scale)
{
	RECT rect;
	POINT point;
	SIZE border;

	GetWindowRect(hCtrl, &rect);
	point.x = (right_to_left_mode && (hDlg != hCtrl))?rect.right:rect.left;
	point.y = rect.top;
	if (hDlg != hCtrl)
		ScreenToClient(hDlg, &point);
	GetClientRect(hCtrl, &rect);

	
	border = GetBorderSize(hCtrl);
	MoveWindow(hCtrl, point.x + (int)(scale*(float)dx), point.y + (int)(scale*(float)dy), (rect.right - rect.left) + (int)(scale*(float)dw + border.cx), (rect.bottom - rect.top) + (int)(scale*(float)dh + border.cy), TRUE);

	InvalidateRect(hCtrl, NULL, TRUE);
}


INT_PTR CALLBACK LicenseCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	long style;
	HWND hLicense;
	switch (message) {
	case WM_INITDIALOG:
		hLicense = GetDlgItem(hDlg, IDC_LICENSE_TEXT);
		apply_localization(IDD_LICENSE, hDlg);
		CenterDialog(hDlg);
		
		style = GetWindowLong(hLicense, GWL_EXSTYLE);
		style &= ~(WS_EX_RTLREADING | WS_EX_RIGHT | WS_EX_LEFTSCROLLBAR);
		SetWindowLong(hLicense, GWL_EXSTYLE, style);
		style = GetWindowLong(hLicense, GWL_STYLE);
		style &= ~(ES_RIGHT);
		SetWindowLong(hLicense, GWL_STYLE, style);
		SetDlgItemTextA(hDlg, IDC_LICENSE_TEXT, gplv3);
		break;
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDOK:
		case IDCANCEL:
			reset_localization(IDD_LICENSE);
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
	}
	return (INT_PTR)FALSE;
}


INT_PTR CALLBACK AboutCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	int i, dy;
	const int edit_id[2] = {IDC_ABOUT_BLURB, IDC_ABOUT_COPYRIGHTS};
	char about_blurb[2048];
	const char* edit_text[2] = {about_blurb, additional_copyrights};
	HWND hEdit[2];
	TEXTRANGEW tr;
	ENLINK* enl;
	RECT rect;
	REQRESIZE* rsz;
	wchar_t wUrl[256];
	static BOOL resized_already = TRUE;

	switch (message) {
	case WM_INITDIALOG:
		resized_already = FALSE;
		
		apply_localization(IDD_ABOUTBOX, hDlg);
		SetTitleBarIcon(hDlg);
		CenterDialog(hDlg);
		if (settings_commcheck)
			ShowWindow(GetDlgItem(hDlg, IDC_ABOUT_UPDATES), SW_SHOW);
		static_sprintf(about_blurb, about_blurb_format, lmprintf(MSG_174|MSG_RTF), lmprintf(MSG_175|MSG_RTF, rufus_version[0], rufus_version[1], rufus_version[2]), right_to_left_mode?"Akeo \\\\ Pete Batard 2011-2017 © Copyright":"Copyright © 2011-2017 Pete Batard / Akeo", lmprintf(MSG_176|MSG_RTF), lmprintf(MSG_177|MSG_RTF), lmprintf(MSG_178|MSG_RTF));


		for (i=0; i<ARRAYSIZE(hEdit); i++) {
			hEdit[i] = GetDlgItem(hDlg, edit_id[i]);
			SendMessage(hEdit[i], EM_AUTOURLDETECT, 1, 0);
			
			SendMessageA(hEdit[i], EM_SETTEXTEX, (WPARAM)&friggin_microsoft_unicode_amateurs, (LPARAM)edit_text[i]);
			SendMessage(hEdit[i], EM_SETSEL, -1, -1);
			SendMessage(hEdit[i], EM_SETEVENTMASK, 0, ENM_LINK|((i==0)?ENM_REQUESTRESIZE:0));
			SendMessage(hEdit[i], EM_SETBKGNDCOLOR, 0, (LPARAM)GetSysColor(COLOR_BTNFACE));
		}
		
		SendMessage(hEdit[1], EM_SETSEL, 0, 0);
		SendMessage(hEdit[0], EM_REQUESTRESIZE, 0, 0);
		break;
	case WM_NOTIFY:
		switch (((LPNMHDR)lParam)->code) {
		case EN_REQUESTRESIZE:
			if (!resized_already) {
				resized_already = TRUE;
				GetWindowRect(GetDlgItem(hDlg, edit_id[0]), &rect);
				dy = rect.bottom - rect.top;
				rsz = (REQRESIZE *)lParam;
				dy -= rsz->rc.bottom - rsz->rc.top;
				ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, edit_id[0]), 0, 0, 0, -dy, 1.0f);
				ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, edit_id[1]), 0, -dy, 0, dy, 1.0f);
			}
			break;
		case EN_LINK:
			enl = (ENLINK*) lParam;
			if (enl->msg == WM_LBUTTONUP) {
				tr.lpstrText = wUrl;
				tr.chrg.cpMin = enl->chrg.cpMin;
				tr.chrg.cpMax = enl->chrg.cpMax;
				SendMessageW(enl->nmhdr.hwndFrom, EM_GETTEXTRANGE, 0, (LPARAM)&tr);
				wUrl[ARRAYSIZE(wUrl)-1] = 0;
				ShellExecuteW(hDlg, L"open", wUrl, NULL, NULL, SW_SHOWNORMAL);
			}
			break;
		}
		break;
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDOK:
		case IDCANCEL:
			reset_localization(IDD_ABOUTBOX);
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		case IDC_ABOUT_LICENSE:
			MyDialogBox(hMainInstance, IDD_LICENSE, hDlg, LicenseCallback);
			break;
		case IDC_ABOUT_UPDATES:
			MyDialogBox(hMainInstance, IDD_UPDATE_POLICY, hDlg, UpdateCallback);
			break;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

INT_PTR CreateAboutBox(void)
{
	INT_PTR r;
	dialog_showing++;
	r = MyDialogBox(hMainInstance, IDD_ABOUTBOX, hMainDialog, AboutCallback);
	dialog_showing--;
	return r;
}


INT_PTR CALLBACK NotificationCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	LRESULT loc;
	int i;
	
	static LRESULT disabled[9] = { HTLEFT, HTRIGHT, HTTOP, HTBOTTOM, HTSIZE, HTTOPLEFT, HTTOPRIGHT, HTBOTTOMLEFT, HTBOTTOMRIGHT };
	static HBRUSH background_brush, separator_brush;
	
	NONCLIENTMETRICS ncm;
	HFONT hDlgFont;

	switch (message) {
	case WM_INITDIALOG:
		if (nWindowsVersion >= WINDOWS_VISTA) {	
			
			ncm.cbSize = sizeof(ncm);
			
			
			#if defined(_MSC_VER) && (_MSC_VER >= 1500) && (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
			ncm.cbSize -= sizeof(ncm.iPaddedBorderWidth);
			#endif
			SystemParametersInfo(SPI_GETNONCLIENTMETRICS, ncm.cbSize, &ncm, 0);
			hDlgFont = CreateFontIndirect(&(ncm.lfMessageFont));
			
			SendMessage(hDlg, WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
			SendMessage(GetDlgItem(hDlg, IDC_NOTIFICATION_TEXT), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
			SendMessage(GetDlgItem(hDlg, IDC_MORE_INFO), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
			SendMessage(GetDlgItem(hDlg, IDYES), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
			SendMessage(GetDlgItem(hDlg, IDNO), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
		}

		apply_localization(IDD_NOTIFICATION, hDlg);
		background_brush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
		separator_brush = CreateSolidBrush(GetSysColor(COLOR_3DLIGHT));
		SetTitleBarIcon(hDlg);
		CenterDialog(hDlg);
		
		if (Static_SetIcon(GetDlgItem(hDlg, IDC_NOTIFICATION_ICON), hMessageIcon) == 0) {
			uprintf("Could not set dialog icon\n");
		}
		
		if (szMessageTitle != NULL) {
			SetWindowTextU(hDlg, szMessageTitle);
		}
		
		if (!notification_is_question) {
			SetWindowTextU(GetDlgItem(hDlg, IDNO), lmprintf(MSG_006));
		} else {
			ShowWindow(GetDlgItem(hDlg, IDYES), SW_SHOW);
		}
		if ((notification_more_info != NULL) && (notification_more_info->callback != NULL)) {
			ShowWindow(GetDlgItem(hDlg, IDC_MORE_INFO), SW_SHOW);
		}
		
		if (szMessageText != NULL) {
			SetWindowTextU(GetDlgItem(hDlg, IDC_NOTIFICATION_TEXT), szMessageText);
		}
		return (INT_PTR)TRUE;
	case WM_CTLCOLORSTATIC:
		
		SetBkMode((HDC)wParam, TRANSPARENT);
		if ((HWND)lParam == GetDlgItem(hDlg, IDC_NOTIFICATION_LINE)) {
			return (INT_PTR)separator_brush;
		}
		return (INT_PTR)background_brush;
	case WM_NCHITTEST:
		
		loc = DefWindowProc(hDlg, message, wParam, lParam);
		for(i = 0; i < 9; i++) {
			if (loc == disabled[i]) {
				return (INT_PTR)TRUE;
			}
		}
		return (INT_PTR)FALSE;
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDOK:
		case IDCANCEL:
		case IDYES:
		case IDNO:
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		case IDC_MORE_INFO:
			if (notification_more_info != NULL)
				MyDialogBox(hMainInstance, notification_more_info->id, hDlg, notification_more_info->callback);
			break;
		}
		break;
	}
	return (INT_PTR)FALSE;
}


BOOL Notification(int type, const notification_info* more_info, char* title, char* format, ...)
{
	BOOL ret;
	va_list args;

	dialog_showing++;
	szMessageText = (char*)malloc(MAX_PATH);
	if (szMessageText == NULL) return FALSE;
	szMessageTitle = safe_strdup(title);
	if (szMessageTitle == NULL) return FALSE;
	va_start(args, format);
	safe_vsnprintf(szMessageText, MAX_PATH-1, format, args);
	va_end(args);
	szMessageText[MAX_PATH-1] = 0;
	notification_more_info = more_info;
	notification_is_question = FALSE;

	switch(type) {
	case MSG_WARNING_QUESTION:
		notification_is_question = TRUE;
		
	case MSG_WARNING:
		hMessageIcon = LoadIcon(NULL, IDI_WARNING);
		break;
	case MSG_ERROR:
		hMessageIcon = LoadIcon(NULL, IDI_ERROR);
		break;
	case MSG_QUESTION:
		hMessageIcon = LoadIcon(NULL, IDI_QUESTION);
		notification_is_question = TRUE;
		break;
	case MSG_INFO:
	default:
		hMessageIcon = LoadIcon(NULL, IDI_INFORMATION);
		break;
	}
	ret = (MyDialogBox(hMainInstance, IDD_NOTIFICATION, hMainDialog, NotificationCallback) == IDYES);
	safe_free(szMessageText);
	safe_free(szMessageTitle);
	dialog_showing--;
	return ret;
}


INT_PTR CALLBACK SelectionCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	LRESULT loc;
	int i, dh, r  = -1;
	
	static LRESULT disabled[9] = { HTLEFT, HTRIGHT, HTTOP, HTBOTTOM, HTSIZE, HTTOPLEFT, HTTOPRIGHT, HTBOTTOMLEFT, HTBOTTOMRIGHT };
	static HBRUSH background_brush, separator_brush;
	
	NONCLIENTMETRICS ncm;
	RECT rect, rect2;
	HFONT hDlgFont;
	HWND hCtrl;
	HDC hDC;

	switch (message) {
	case WM_INITDIALOG:
		
		if (nDialogItems > (IDC_SELECTION_CHOICEMAX - IDC_SELECTION_CHOICE1 + 1)) {
			uprintf("Warning: Too many options requested for Selection (%d vs %d)", nDialogItems, IDC_SELECTION_CHOICEMAX - IDC_SELECTION_CHOICE1);
			nDialogItems = IDC_SELECTION_CHOICEMAX - IDC_SELECTION_CHOICE1;
		}
		
		
		ncm.cbSize = sizeof(ncm);
		
		

		if (nWindowsVersion >= WINDOWS_VISTA) {
			
			
			ncm.cbSize -= sizeof(ncm.iPaddedBorderWidth);
		}

		SystemParametersInfo(SPI_GETNONCLIENTMETRICS, ncm.cbSize, &ncm, 0);
		hDlgFont = CreateFontIndirect(&(ncm.lfMessageFont));
		
		SendMessage(hDlg, WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
		SendMessage(GetDlgItem(hDlg, IDC_SELECTION_TEXT), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
		for (i = 0; i < nDialogItems; i++)
			SendMessage(GetDlgItem(hDlg, IDC_SELECTION_CHOICE1 + i), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
		SendMessage(GetDlgItem(hDlg, IDYES), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
		SendMessage(GetDlgItem(hDlg, IDNO), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));

		apply_localization(IDD_SELECTION, hDlg);
		background_brush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
		separator_brush = CreateSolidBrush(GetSysColor(COLOR_3DLIGHT));
		SetTitleBarIcon(hDlg);
		CenterDialog(hDlg);
		
		Static_SetIcon(GetDlgItem(hDlg, IDC_SELECTION_ICON), LoadIcon(NULL, IDI_QUESTION));
		SetWindowTextU(hDlg, szMessageTitle);
		SetWindowTextU(GetDlgItem(hDlg, IDCANCEL), lmprintf(MSG_007));
		SetWindowTextU(GetDlgItem(hDlg, IDC_SELECTION_TEXT), szMessageText);
		for (i = 0; i < nDialogItems; i++) {
			SetWindowTextU(GetDlgItem(hDlg, IDC_SELECTION_CHOICE1 + i), szDialogItem[i]);
			ShowWindow(GetDlgItem(hDlg, IDC_SELECTION_CHOICE1 + i), SW_SHOW);
		}
		
		hCtrl = GetDlgItem(hDlg, IDC_SELECTION_TEXT);
		hDC = GetDC(hCtrl);
		SelectFont(hDC, hDlgFont);	
		GetWindowRect(hCtrl, &rect);
		dh = rect.bottom - rect.top;
		DrawTextU(hDC, szMessageText, -1, &rect, DT_CALCRECT | DT_WORDBREAK);
		dh = rect.bottom - rect.top - dh;
		if (hDC != NULL)
			ReleaseDC(hCtrl, hDC);
		ResizeMoveCtrl(hDlg, hCtrl, 0, 0, 0, dh, 1.0f);
		for (i = 0; i < nDialogItems; i++)
			ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDC_SELECTION_CHOICE1 + i), 0, dh, 0, 0, 1.0f);
		if (nDialogItems > 2) {
			GetWindowRect(GetDlgItem(hDlg, IDC_SELECTION_CHOICE2), &rect);
			GetWindowRect(GetDlgItem(hDlg, IDC_SELECTION_CHOICE1 + nDialogItems - 1), &rect2);
			dh += rect2.top - rect.top;
		}
		ResizeMoveCtrl(hDlg, hDlg, 0, 0, 0, dh, 1.0f);
		ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, -1), 0, 0, 0, dh, 1.0f);	
		ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDC_SELECTION_LINE), 0, dh, 0, 0, 1.0f);
		ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDOK), 0, dh, 0, 0, 1.0f);
		ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDCANCEL), 0, dh, 0, 0, 1.0f);

		
		Button_SetCheck(GetDlgItem(hDlg, IDC_SELECTION_CHOICE1), BST_CHECKED);
		Button_SetCheck(GetDlgItem(hDlg, IDC_SELECTION_CHOICE2), BST_UNCHECKED);
		return (INT_PTR)TRUE;
	case WM_CTLCOLORSTATIC:
		
		SetBkMode((HDC)wParam, TRANSPARENT);
		if ((HWND)lParam == GetDlgItem(hDlg, IDC_NOTIFICATION_LINE)) {
			return (INT_PTR)separator_brush;
		}
		return (INT_PTR)background_brush;
	case WM_NCHITTEST:
		
		loc = DefWindowProc(hDlg, message, wParam, lParam);
		for (i = 0; i < 9; i++) {
			if (loc == disabled[i]) {
				return (INT_PTR)TRUE;
			}
		}
		return (INT_PTR)FALSE;
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDOK:
			for (i = 0; (i < nDialogItems) && (Button_GetCheck(GetDlgItem(hDlg, IDC_SELECTION_CHOICE1 + i)) != BST_CHECKED); i++);
			if (i < nDialogItems)
				r = i + 1;
			
		case IDNO:
		case IDCANCEL:
			EndDialog(hDlg, r);
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}


int SelectionDialog(char* title, char* message, char** choices, int size)
{
	int ret;

	dialog_showing++;
	szMessageTitle = title;
	szMessageText = message;
	szDialogItem = choices;
	nDialogItems = size;
	ret = (int)MyDialogBox(hMainInstance, IDD_SELECTION, hMainDialog, SelectionCallback);
	dialog_showing--;

	return ret;
}


INT_PTR CALLBACK ListCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	LRESULT loc;
	int i, dh, r  = -1;
	
	static LRESULT disabled[9] = { HTLEFT, HTRIGHT, HTTOP, HTBOTTOM, HTSIZE, HTTOPLEFT, HTTOPRIGHT, HTBOTTOMLEFT, HTBOTTOMRIGHT };
	static HBRUSH background_brush, separator_brush;
	
	NONCLIENTMETRICS ncm;
	RECT rect, rect2;
	HFONT hDlgFont;
	HWND hCtrl;
	HDC hDC;

	switch (message) {
	case WM_INITDIALOG:
		
		if (nDialogItems > (IDC_LIST_ITEMMAX - IDC_LIST_ITEM1 + 1)) {
			uprintf("Warning: Too many items requested for List (%d vs %d)", nDialogItems, IDC_LIST_ITEMMAX - IDC_LIST_ITEM1);
			nDialogItems = IDC_LIST_ITEMMAX - IDC_LIST_ITEM1;
		}
		
		
		ncm.cbSize = sizeof(ncm);
		
		

		if (nWindowsVersion >= WINDOWS_VISTA) {
			
			
			ncm.cbSize -= sizeof(ncm.iPaddedBorderWidth);
		}

		SystemParametersInfo(SPI_GETNONCLIENTMETRICS, ncm.cbSize, &ncm, 0);
		hDlgFont = CreateFontIndirect(&(ncm.lfMessageFont));
		
		SendMessage(hDlg, WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
		SendMessage(GetDlgItem(hDlg, IDC_LIST_TEXT), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
		for (i = 0; i < nDialogItems; i++)
			SendMessage(GetDlgItem(hDlg, IDC_LIST_ITEM1 + i), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
		SendMessage(GetDlgItem(hDlg, IDYES), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));
		SendMessage(GetDlgItem(hDlg, IDNO), WM_SETFONT, (WPARAM)hDlgFont, MAKELPARAM(TRUE, 0));

		apply_localization(IDD_LIST, hDlg);
		background_brush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
		separator_brush = CreateSolidBrush(GetSysColor(COLOR_3DLIGHT));
		SetTitleBarIcon(hDlg);
		CenterDialog(hDlg);
		
		Static_SetIcon(GetDlgItem(hDlg, IDC_LIST_ICON), LoadIcon(NULL, IDI_EXCLAMATION));
		SetWindowTextU(hDlg, szMessageTitle);
		SetWindowTextU(GetDlgItem(hDlg, IDCANCEL), lmprintf(MSG_007));
		SetWindowTextU(GetDlgItem(hDlg, IDC_LIST_TEXT), szMessageText);
		for (i = 0; i < nDialogItems; i++) {
			SetWindowTextU(GetDlgItem(hDlg, IDC_LIST_ITEM1 + i), szDialogItem[i]);
			ShowWindow(GetDlgItem(hDlg, IDC_LIST_ITEM1 + i), SW_SHOW);
		}
		
		hCtrl = GetDlgItem(hDlg, IDC_LIST_TEXT);
		hDC = GetDC(hCtrl);
		SelectFont(hDC, hDlgFont);	
		GetWindowRect(hCtrl, &rect);
		dh = rect.bottom - rect.top;
		DrawTextU(hDC, szMessageText, -1, &rect, DT_CALCRECT | DT_WORDBREAK);
		dh = rect.bottom - rect.top - dh;
		if (hDC != NULL)
			ReleaseDC(hCtrl, hDC);
		ResizeMoveCtrl(hDlg, hCtrl, 0, 0, 0, dh, 1.0f);
		for (i = 0; i < nDialogItems; i++)
			ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDC_LIST_ITEM1 + i), 0, dh, 0, 0, 1.0f);
		if (nDialogItems > 1) {
			GetWindowRect(GetDlgItem(hDlg, IDC_LIST_ITEM1), &rect);
			GetWindowRect(GetDlgItem(hDlg, IDC_LIST_ITEM1 + nDialogItems - 1), &rect2);
			dh += rect2.top - rect.top;
		}
		ResizeMoveCtrl(hDlg, hDlg, 0, 0, 0, dh, 1.0f);
		ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, -1), 0, 0, 0, dh, 1.0f);	
		ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDC_LIST_LINE), 0, dh, 0, 0, 1.0f);
		ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDOK), 0, dh, 0, 0, 1.0f);
		ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDCANCEL), 0, dh, 0, 0, 1.0f);
		return (INT_PTR)TRUE;
	case WM_CTLCOLORSTATIC:
		
		SetBkMode((HDC)wParam, TRANSPARENT);
		if ((HWND)lParam == GetDlgItem(hDlg, IDC_NOTIFICATION_LINE)) {
			return (INT_PTR)separator_brush;
		}
		return (INT_PTR)background_brush;
	case WM_NCHITTEST:
		
		loc = DefWindowProc(hDlg, message, wParam, lParam);
		for (i = 0; i < 9; i++) {
			if (loc == disabled[i]) {
				return (INT_PTR)TRUE;
			}
		}
		return (INT_PTR)FALSE;
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDOK:
		case IDNO:
		case IDCANCEL:
			EndDialog(hDlg, r);
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}


void ListDialog(char* title, char* message, char** items, int size)
{
	dialog_showing++;
	szMessageTitle = title;
	szMessageText = message;
	szDialogItem = items;
	nDialogItems = size;
	MyDialogBox(hMainInstance, IDD_LIST, hMainDialog, ListCallback);
	dialog_showing--;
}

static struct {
	HWND hTip;		
	HWND hCtrl;		
	WNDPROC original_proc;
	LPWSTR wstring;
} ttlist[MAX_TOOLTIPS] = { {0} };

INT_PTR CALLBACK TooltipCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	LPNMTTDISPINFOW lpnmtdi;
	int i = MAX_TOOLTIPS;

	
	for (i=0; i<MAX_TOOLTIPS; i++) {
		if (ttlist[i].hTip == hDlg) break;
	}
	if (i == MAX_TOOLTIPS)
		return (INT_PTR)FALSE;

	switch (message) {
	case WM_NOTIFY:
		switch (((LPNMHDR)lParam)->code) {
		case TTN_GETDISPINFOW:
			lpnmtdi = (LPNMTTDISPINFOW)lParam;
			lpnmtdi->lpszText = ttlist[i].wstring;
			SendMessage(hDlg, TTM_SETMAXTIPWIDTH, 0, 300);
			return (INT_PTR)TRUE;
		}
		break;
	}

	
	if (GetCurrentThreadId() != MainThreadId)
		uprintf("Warning: Tooltip callback is being called from wrong thread");

	return CallWindowProc(ttlist[i].original_proc, hDlg, message, wParam, lParam);
}


BOOL CreateTooltip(HWND hControl, const char* message, int duration)
{
	TOOLINFOW toolInfo = {0};
	int i;

	if ( (hControl == NULL) || (message == NULL) ) {
		return FALSE;
	}

	
	DestroyTooltip(hControl);

	
	for (i=0; i<MAX_TOOLTIPS; i++) {
		if (ttlist[i].hTip == NULL) break;
	}
	if (i >= MAX_TOOLTIPS) {
		uprintf("Maximum number of tooltips reached (%d)\n", MAX_TOOLTIPS);
		return FALSE;
	}

	
	ttlist[i].hTip = CreateWindowExW(0, TOOLTIPS_CLASS, NULL, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hMainDialog, NULL, hMainInstance, NULL);


	if (ttlist[i].hTip == NULL) {
		return FALSE;
	}
	ttlist[i].hCtrl = hControl;

	
	ttlist[i].original_proc = (WNDPROC)SetWindowLongPtr(ttlist[i].hTip, GWLP_WNDPROC, (LONG_PTR)TooltipCallback);

	
	ttlist[i].wstring = utf8_to_wchar(message);

	
	PostMessage(ttlist[i].hTip, TTM_SETDELAYTIME, (WPARAM)TTDT_AUTOPOP, (LPARAM)duration);

	
	toolInfo.cbSize = sizeof(toolInfo);
	toolInfo.hwnd = ttlist[i].hTip;	
	toolInfo.uFlags = TTF_IDISHWND | TTF_SUBCLASS | ((right_to_left_mode)?TTF_RTLREADING:0);
	
	if (!(SendMessage(hControl, WM_GETDLGCODE, 0, 0) & DLGC_BUTTON))
		toolInfo.uFlags |= 0x80000000L | TTF_CENTERTIP;

	toolInfo.uId = (UINT_PTR)hControl;
	toolInfo.lpszText = LPSTR_TEXTCALLBACKW;
	SendMessageW(ttlist[i].hTip, TTM_ADDTOOLW, 0, (LPARAM)&toolInfo);

	return TRUE;
}


void DestroyTooltip(HWND hControl)
{
	int i;

	if (hControl == NULL) return;
	for (i=0; i<MAX_TOOLTIPS; i++) {
		if (ttlist[i].hCtrl == hControl) break;
	}
	if (i >= MAX_TOOLTIPS) return;
	DestroyWindow(ttlist[i].hTip);
	safe_free(ttlist[i].wstring);
	ttlist[i].original_proc = NULL;
	ttlist[i].hTip = NULL;
	ttlist[i].hCtrl = NULL;
}

void DestroyAllTooltips(void)
{
	int i, j;

	for (i=0, j=0; i<MAX_TOOLTIPS; i++) {
		if (ttlist[i].hTip == NULL) continue;
		j++;
		DestroyWindow(ttlist[i].hTip);
		safe_free(ttlist[i].wstring);
		ttlist[i].original_proc = NULL;
		ttlist[i].hTip = NULL;
		ttlist[i].hCtrl = NULL;
	}
}


BOOL IsShown(HWND hDlg)
{
	WINDOWPLACEMENT placement = {0};
	placement.length = sizeof(WINDOWPLACEMENT);
	if (!GetWindowPlacement(hDlg, &placement))
		return FALSE;
	switch (placement.showCmd) {
	case SW_SHOWNORMAL:
	case SW_SHOWMAXIMIZED:
	case SW_SHOW:
	case SW_SHOWDEFAULT:
		return TRUE;
	default:
		return FALSE;
	}
}


LONG GetEntryWidth(HWND hDropDown, const char *entry)
{
	HDC hDC;
	HFONT hFont, hDefFont = NULL;
	SIZE size;

	hDC = GetDC(hDropDown);
	hFont = (HFONT)SendMessage(hDropDown, WM_GETFONT, 0, 0);
	if (hFont != NULL)
		hDefFont = (HFONT)SelectObject(hDC, hFont);

	if (!GetTextExtentPointU(hDC, entry, &size))
		size.cx = 0;

	if (hFont != NULL)
		SelectObject(hDC, hDefFont);

	if (hDC != NULL)
		ReleaseDC(hDropDown, hDC);
	return size.cx;
}


typedef enum MY_STPFLAG {
	MY_STPF_NONE = 0, MY_STPF_USEAPPTHUMBNAILALWAYS = 0x1, MY_STPF_USEAPPTHUMBNAILWHENACTIVE = 0x2, MY_STPF_USEAPPPEEKALWAYS = 0x4, MY_STPF_USEAPPPEEKWHENACTIVE = 0x8 } MY_STPFLAG;





typedef enum MY_THUMBBUTTONMASK {
	MY_THB_BITMAP = 0x1, MY_THB_ICON = 0x2, MY_THB_TOOLTIP = 0x4, MY_THB_FLAGS = 0x8 } MY_THUMBBUTTONMASK;




typedef enum MY_THUMBBUTTONFLAGS {
	MY_THBF_ENABLED = 0, MY_THBF_DISABLED = 0x1, MY_THBF_DISMISSONCLICK = 0x2, MY_THBF_NOBACKGROUND = 0x4, MY_THBF_HIDDEN = 0x8, MY_THBF_NONINTERACTIVE = 0x10 } MY_THUMBBUTTONFLAGS;






typedef struct MY_THUMBBUTTON {
	MY_THUMBBUTTONMASK dwMask;
	UINT iId;
	UINT iBitmap;
	HICON hIcon;
	WCHAR szTip[260];
	MY_THUMBBUTTONFLAGS dwFlags;
} MY_THUMBBUTTON;






DECLARE_INTERFACE_(my_ITaskbarList3, IUnknown) {
	STDMETHOD (QueryInterface) (THIS_ REFIID riid, LPVOID *ppvObj) PURE;
	STDMETHOD_(ULONG, AddRef) (THIS) PURE;
	STDMETHOD_(ULONG, Release) (THIS) PURE;
	STDMETHOD (HrInit) (THIS) PURE;
	STDMETHOD (AddTab) (THIS_ HWND hwnd) PURE;
	STDMETHOD (DeleteTab) (THIS_ HWND hwnd) PURE;
	STDMETHOD (ActivateTab) (THIS_ HWND hwnd) PURE;
	STDMETHOD (SetActiveAlt) (THIS_ HWND hwnd) PURE;
	STDMETHOD (MarkFullscreenWindow) (THIS_ HWND hwnd, int fFullscreen) PURE;
	STDMETHOD (SetProgressValue) (THIS_ HWND hwnd, ULONGLONG ullCompleted, ULONGLONG ullTotal) PURE;
	STDMETHOD (SetProgressState) (THIS_ HWND hwnd, TASKBAR_PROGRESS_FLAGS tbpFlags) PURE;
	STDMETHOD (RegisterTab) (THIS_ HWND hwndTab,HWND hwndMDI) PURE;
	STDMETHOD (UnregisterTab) (THIS_ HWND hwndTab) PURE;
	STDMETHOD (SetTabOrder) (THIS_ HWND hwndTab, HWND hwndInsertBefore) PURE;
	STDMETHOD (SetTabActive) (THIS_ HWND hwndTab, HWND hwndMDI, DWORD dwReserved) PURE;
	STDMETHOD (ThumbBarAddButtons) (THIS_ HWND hwnd, UINT cButtons, MY_THUMBBUTTON* pButton) PURE;
	STDMETHOD (ThumbBarUpdateButtons) (THIS_ HWND hwnd, UINT cButtons, MY_THUMBBUTTON* pButton) PURE;
	STDMETHOD (ThumbBarSetImageList) (THIS_ HWND hwnd, HIMAGELIST himl) PURE;
	STDMETHOD (SetOverlayIcon) (THIS_ HWND hwnd, HICON hIcon, LPCWSTR pszDescription) PURE;
	STDMETHOD (SetThumbnailTooltip) (THIS_ HWND hwnd, LPCWSTR pszTip) PURE;
	STDMETHOD (SetThumbnailClip) (THIS_ HWND hwnd, RECT *prcClip) PURE;
};
const IID my_IID_ITaskbarList3 = { 0xea1afb91, 0x9e28, 0x4b86, { 0x90, 0xe9, 0x9e, 0x9f, 0x8a, 0x5e, 0xef, 0xaf } };
const IID my_CLSID_TaskbarList = { 0x56fdf344, 0xfd6d, 0x11d0, { 0x95, 0x8a ,0x0, 0x60, 0x97, 0xc9, 0xa0 ,0x90 } };

static my_ITaskbarList3* ptbl = NULL;


BOOL CreateTaskbarList(void)
{
	HRESULT hr;
	if (nWindowsVersion < WINDOWS_7)
		
		return FALSE;
	hr = CoCreateInstance(&my_CLSID_TaskbarList, NULL, CLSCTX_ALL, &my_IID_ITaskbarList3, (LPVOID)&ptbl);
	if (FAILED(hr)) {
		uprintf("CoCreateInstance for TaskbarList failed: error %X\n", hr);
		ptbl = NULL;
		return FALSE;
	}
	return TRUE;
}

BOOL SetTaskbarProgressState(TASKBAR_PROGRESS_FLAGS tbpFlags)
{
	if (ptbl == NULL)
		return FALSE;
	return !FAILED(ptbl->lpVtbl->SetProgressState(ptbl, hMainDialog, tbpFlags));
}

BOOL SetTaskbarProgressValue(ULONGLONG ullCompleted, ULONGLONG ullTotal)
{
	if (ptbl == NULL)
		return FALSE;
	return !FAILED(ptbl->lpVtbl->SetProgressValue(ptbl, hMainDialog, ullCompleted, ullTotal));
}




INT_PTR CALLBACK UpdateCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	int dy;
	RECT rect;
	REQRESIZE* rsz;
	HWND hPolicy;
	static HWND hFrequency, hBeta;
	int32_t freq;
	char update_policy_text[4096];
	static BOOL resized_already = TRUE;

	switch (message) {
	case WM_INITDIALOG:
		resized_already = FALSE;
		hUpdatesDlg = hDlg;
		apply_localization(IDD_UPDATE_POLICY, hDlg);
		SetTitleBarIcon(hDlg);
		CenterDialog(hDlg);
		hFrequency = GetDlgItem(hDlg, IDC_UPDATE_FREQUENCY);
		hBeta = GetDlgItem(hDlg, IDC_INCLUDE_BETAS);
		IGNORE_RETVAL(ComboBox_SetItemData(hFrequency, ComboBox_AddStringU(hFrequency, lmprintf(MSG_013)), -1));
		IGNORE_RETVAL(ComboBox_SetItemData(hFrequency, ComboBox_AddStringU(hFrequency, lmprintf(MSG_030, lmprintf(MSG_014))), 86400));
		IGNORE_RETVAL(ComboBox_SetItemData(hFrequency, ComboBox_AddStringU(hFrequency, lmprintf(MSG_015)), 604800));
		IGNORE_RETVAL(ComboBox_SetItemData(hFrequency, ComboBox_AddStringU(hFrequency, lmprintf(MSG_016)), 2629800));
		freq = ReadSetting32(SETTING_UPDATE_INTERVAL);
		EnableWindow(GetDlgItem(hDlg, IDC_CHECK_NOW), (freq != 0));
		EnableWindow(hBeta, (freq >= 0));
		switch(freq) {
		case -1:
			IGNORE_RETVAL(ComboBox_SetCurSel(hFrequency, 0));
			break;
		case 0:
		case 86400:
			IGNORE_RETVAL(ComboBox_SetCurSel(hFrequency, 1));
			break;
		case 604800:
			IGNORE_RETVAL(ComboBox_SetCurSel(hFrequency, 2));
			break;
		case 2629800:
			IGNORE_RETVAL(ComboBox_SetCurSel(hFrequency, 3));
			break;
		default:
			IGNORE_RETVAL(ComboBox_SetItemData(hFrequency, ComboBox_AddStringU(hFrequency, lmprintf(MSG_017)), freq));
			IGNORE_RETVAL(ComboBox_SetCurSel(hFrequency, 4));
			break;
		}
		IGNORE_RETVAL(ComboBox_AddStringU(hBeta, lmprintf(MSG_008)));
		IGNORE_RETVAL(ComboBox_AddStringU(hBeta, lmprintf(MSG_009)));
		IGNORE_RETVAL(ComboBox_SetCurSel(hBeta, ReadSettingBool(SETTING_INCLUDE_BETAS)?0:1));
		hPolicy = GetDlgItem(hDlg, IDC_POLICY);
		SendMessage(hPolicy, EM_AUTOURLDETECT, 1, 0);
		static_sprintf(update_policy_text, update_policy, lmprintf(MSG_179|MSG_RTF), lmprintf(MSG_180|MSG_RTF), lmprintf(MSG_181|MSG_RTF), lmprintf(MSG_182|MSG_RTF), lmprintf(MSG_183|MSG_RTF), lmprintf(MSG_184|MSG_RTF), lmprintf(MSG_185|MSG_RTF), lmprintf(MSG_186|MSG_RTF));

		SendMessageA(hPolicy, EM_SETTEXTEX, (WPARAM)&friggin_microsoft_unicode_amateurs, (LPARAM)update_policy_text);
		SendMessage(hPolicy, EM_SETSEL, -1, -1);
		SendMessage(hPolicy, EM_SETEVENTMASK, 0, ENM_LINK|ENM_REQUESTRESIZE);
		SendMessageA(hPolicy, EM_SETBKGNDCOLOR, 0, (LPARAM)GetSysColor(COLOR_BTNFACE));
		SendMessage(hPolicy, EM_REQUESTRESIZE, 0, 0);
		break;
	case WM_NOTIFY:
		if ((((LPNMHDR)lParam)->code == EN_REQUESTRESIZE) && (!resized_already)) {
			resized_already = TRUE;
			hPolicy = GetDlgItem(hDlg, IDC_POLICY);
			GetWindowRect(hPolicy, &rect);
			dy = rect.bottom - rect.top;
			rsz = (REQRESIZE *)lParam;
			dy -= rsz->rc.bottom - rsz->rc.top + 6;	
			ResizeMoveCtrl(hDlg, hDlg, 0, 0, 0, -dy, 1.0f);
			ResizeMoveCtrl(hDlg, hPolicy, 0, 0, 0, -dy, 1.0f);
			ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDS_UPDATE_SETTINGS_GRP), 0, -dy, 0, 0, 1.0f);
			ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDS_UPDATE_FREQUENCY_TXT), 0, -dy, 0, 0, 1.0f);
			ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDC_UPDATE_FREQUENCY), 0, -dy, 0, 0, 1.0f);
			ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDS_INCLUDE_BETAS_TXT), 0, -dy, 0, 0, 1.0f);
			ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDC_INCLUDE_BETAS), 0, -dy, 0, 0, 1.0f);
			ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDS_CHECK_NOW_GRP), 0, -dy, 0, 0, 1.0f);
			ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDC_CHECK_NOW), 0, -dy, 0, 0, 1.0f);
			ResizeMoveCtrl(hDlg, GetDlgItem(hDlg, IDCANCEL), 0, -dy, 0, 0, 1.0f);
		}
		break;
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDCLOSE:
		case IDCANCEL:
			reset_localization(IDD_UPDATE_POLICY);
			EndDialog(hDlg, LOWORD(wParam));
			hUpdatesDlg = NULL;
			return (INT_PTR)TRUE;
		case IDC_CHECK_NOW:
			CheckForUpdates(TRUE);
			return (INT_PTR)TRUE;
		case IDC_UPDATE_FREQUENCY:
			if (HIWORD(wParam) != CBN_SELCHANGE)
				break;
			freq = (int32_t)ComboBox_GetItemData(hFrequency, ComboBox_GetCurSel(hFrequency));
			WriteSetting32(SETTING_UPDATE_INTERVAL, (DWORD)freq);
			EnableWindow(hBeta, (freq >= 0));
			return (INT_PTR)TRUE;
		case IDC_INCLUDE_BETAS:
			if (HIWORD(wParam) != CBN_SELCHANGE)
				break;
			WriteSettingBool(SETTING_INCLUDE_BETAS, ComboBox_GetCurSel(hBeta) == 0);
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}


BOOL SetUpdateCheck(void)
{
	BOOL enable_updates;
	uint64_t commcheck = _GetTickCount64();
	notification_info more_info = { IDD_UPDATE_POLICY, UpdateCallback };
	char filename[MAX_PATH] = "", exename[] = APPLICATION_NAME ".exe";
	size_t fn_len, exe_len;

	
	WriteSetting64(SETTING_COMM_CHECK, commcheck);
	if (ReadSetting64(SETTING_COMM_CHECK) != commcheck)
		return FALSE;
	settings_commcheck = TRUE;

	
	if (ReadSetting32(SETTING_UPDATE_INTERVAL) == 0) {

		
		
		GetModuleFileNameU(NULL, filename, sizeof(filename));
		fn_len = safe_strlen(filename);
		exe_len = safe_strlen(exename);

		if ((fn_len > exe_len) && (safe_stricmp(&filename[fn_len-exe_len], exename) == 0)) {
			uprintf("Short name used - Disabling initial update policy prompt\n");
			enable_updates = TRUE;
		} else {

			enable_updates = Notification(MSG_QUESTION, &more_info, lmprintf(MSG_004), lmprintf(MSG_005));

		}

		if (!enable_updates) {
			WriteSetting32(SETTING_UPDATE_INTERVAL, -1);
			return FALSE;
		}
		
		if ( (ReadSetting32(SETTING_UPDATE_INTERVAL) == 0) || ((ReadSetting32(SETTING_UPDATE_INTERVAL) == -1) && enable_updates) )
			WriteSetting32(SETTING_UPDATE_INTERVAL, 86400);
	}
	return TRUE;
}

static void CreateStaticFont(HDC dc, HFONT* hyperlink_font) {
	TEXTMETRIC tm;
	LOGFONT lf;

	if (*hyperlink_font != NULL)
		return;
	GetTextMetrics(dc, &tm);
	lf.lfHeight = tm.tmHeight;
	lf.lfWidth = 0;
	lf.lfEscapement = 0;
	lf.lfOrientation = 0;
	lf.lfWeight = tm.tmWeight;
	lf.lfItalic = tm.tmItalic;
	lf.lfUnderline = TRUE;
	lf.lfStrikeOut = tm.tmStruckOut;
	lf.lfCharSet = tm.tmCharSet;
	lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
	lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
	lf.lfQuality = DEFAULT_QUALITY;
	lf.lfPitchAndFamily = tm.tmPitchAndFamily;
	GetTextFace(dc, LF_FACESIZE, lf.lfFaceName);
	*hyperlink_font = CreateFontIndirect(&lf);
}


INT_PTR CALLBACK update_subclass_callback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_SETCURSOR:
		if ((HWND)wParam == GetDlgItem(hDlg, IDC_WEBSITE)) {
			SetCursor(LoadCursor(NULL, IDC_HAND));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return CallWindowProc(update_original_proc, hDlg, message, wParam, lParam);
}


INT_PTR CALLBACK NewVersionCallback(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	char cmdline[] = APPLICATION_NAME " -w 150";
	static char* filepath = NULL;
	static int download_status = 0;
	LONG i;
	HWND hNotes;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	HFONT hyperlink_font = NULL;
	EXT_DECL(dl_ext, NULL, __VA_GROUP__("*.exe"), __VA_GROUP__(lmprintf(MSG_037)));

	switch (message) {
	case WM_INITDIALOG:
		apply_localization(IDD_NEW_VERSION, hDlg);
		download_status = 0;
		SetTitleBarIcon(hDlg);
		CenterDialog(hDlg);
		
		update_original_proc = (WNDPROC)SetWindowLongPtr(hDlg, GWLP_WNDPROC, (LONG_PTR)update_subclass_callback);
		hNotes = GetDlgItem(hDlg, IDC_RELEASE_NOTES);
		SendMessage(hNotes, EM_AUTOURLDETECT, 1, 0);
		SendMessageA(hNotes, EM_SETTEXTEX, (WPARAM)&friggin_microsoft_unicode_amateurs, (LPARAM)update.release_notes);
		SendMessage(hNotes, EM_SETSEL, -1, -1);
		SendMessage(hNotes, EM_SETEVENTMASK, 0, ENM_LINK);
		SetWindowTextU(GetDlgItem(hDlg, IDC_YOUR_VERSION), lmprintf(MSG_018, rufus_version[0], rufus_version[1], rufus_version[2]));
		SetWindowTextU(GetDlgItem(hDlg, IDC_LATEST_VERSION), lmprintf(MSG_019, update.version[0], update.version[1], update.version[2]));
		SetWindowTextU(GetDlgItem(hDlg, IDC_DOWNLOAD_URL), update.download_url);
		SendMessage(GetDlgItem(hDlg, IDC_PROGRESS), PBM_SETRANGE, 0, (MAX_PROGRESS<<16) & 0xFFFF0000);
		if (update.download_url == NULL)
			EnableWindow(GetDlgItem(hDlg, IDC_DOWNLOAD), FALSE);
		break;
	case WM_CTLCOLORSTATIC:
		if ((HWND)lParam != GetDlgItem(hDlg, IDC_WEBSITE))
			return FALSE;
		
		SetBkMode((HDC)wParam, TRANSPARENT);
		CreateStaticFont((HDC)wParam, &hyperlink_font);
		SelectObject((HDC)wParam, hyperlink_font);
		SetTextColor((HDC)wParam, RGB(0,0,125));	
		return (INT_PTR)CreateSolidBrush(GetSysColor(COLOR_BTNFACE));
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDCLOSE:
		case IDCANCEL:
			if (download_status != 1) {
				reset_localization(IDD_NEW_VERSION);
				safe_free(filepath);
				EndDialog(hDlg, LOWORD(wParam));
			}
			return (INT_PTR)TRUE;
		case IDC_WEBSITE:
			ShellExecuteA(hDlg, "open", RUFUS_URL, NULL, NULL, SW_SHOWNORMAL);
			break;
		case IDC_DOWNLOAD:	
			switch(download_status) {
			case 1:		
				FormatStatus = ERROR_SEVERITY_ERROR|FAC(FACILITY_STORAGE)|ERROR_CANCELLED;
				download_status = 0;
				break;
			case 2:		
				Sleep(1000);	

				if (ValidateSignature(hDlg, filepath) != NO_ERROR)
					break;

				memset(&si, 0, sizeof(si));
				memset(&pi, 0, sizeof(pi));
				si.cb = sizeof(si);
				if (!CreateProcessU(filepath, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
					PrintInfo(0, MSG_214);
					uprintf("Failed to launch new application: %s\n", WindowsErrorString());
				} else {
					PrintInfo(0, MSG_213);
					PostMessage(hDlg, WM_COMMAND, (WPARAM)IDCLOSE, 0);
					PostMessage(hMainDialog, WM_CLOSE, 0, 0);
				}
				break;
			default:	
				if (update.download_url == NULL) {
					uprintf("Could not get download URL\n");
					break;
				}
				for (i=(int)strlen(update.download_url); (i>0)&&(update.download_url[i]!='/'); i--);
				dl_ext.filename = &update.download_url[i+1];
				filepath = FileDialog(TRUE, app_dir, &dl_ext, OFN_NOCHANGEDIR);
				if (filepath == NULL) {
					uprintf("Could not get save path\n");
					break;
				}
				
				SendMessage(hDlg, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hDlg, IDC_DOWNLOAD), TRUE);
				DownloadFileThreaded(update.download_url, filepath, hDlg);
				break;
			}
			return (INT_PTR)TRUE;
		}
		break;
	case UM_PROGRESS_INIT:
		EnableWindow(GetDlgItem(hDlg, IDCANCEL), FALSE);
		SetWindowTextU(GetDlgItem(hDlg, IDC_DOWNLOAD), lmprintf(MSG_038));
		FormatStatus = 0;
		download_status = 1;
		return (INT_PTR)TRUE;
	case UM_PROGRESS_EXIT:
		EnableWindow(GetDlgItem(hDlg, IDCANCEL), TRUE);
		if (wParam) {
			SetWindowTextU(GetDlgItem(hDlg, IDC_DOWNLOAD), lmprintf(MSG_039));
			download_status = 2;
		} else {
			SetWindowTextU(GetDlgItem(hDlg, IDC_DOWNLOAD), lmprintf(MSG_040));
			download_status = 0;
		}
		return (INT_PTR)TRUE;
	}
	return (INT_PTR)FALSE;
}

void DownloadNewVersion(void)
{
	MyDialogBox(hMainInstance, IDD_NEW_VERSION, hMainDialog, NewVersionCallback);
}

void SetTitleBarIcon(HWND hDlg)
{
	int i16, s16, s32;
	HICON hSmallIcon, hBigIcon;

	
	i16 = GetSystemMetrics(SM_CXSMICON);
	
	s16 = i16;
	s32 = (int)(32.0f*fScale);
	if (s16 >= 54)
		s16 = 64;
	else if (s16 >= 40)
		s16 = 48;
	else if (s16 >= 28)
		s16 = 32;
	else if (s16 >= 20)
		s16 = 24;
	if (s32 >= 54)
		s32 = 64;
	else if (s32 >= 40)
		s32 = 48;
	else if (s32 >= 28)
		s32 = 32;
	else if (s32 >= 20)
		s32 = 24;

	
	hSmallIcon = (HICON)LoadImage(hMainInstance, MAKEINTRESOURCE(IDI_ICON), IMAGE_ICON, s16, s16, 0);
	SendMessage (hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hSmallIcon);
	hBigIcon = (HICON)LoadImage(hMainInstance, MAKEINTRESOURCE(IDI_ICON), IMAGE_ICON, s32, s32, 0);
	SendMessage (hDlg, WM_SETICON, ICON_BIG, (LPARAM)hBigIcon);
}


SIZE GetTextSize(HWND hCtrl)
{
	SIZE sz = {0, 0};
	HDC hDC;
	wchar_t *wstr = NULL;
	int len;
	HFONT hFont;

	
	hDC = GetDC(hCtrl);
	if (hDC == NULL)
		goto out;
	hFont = (HFONT)SendMessageA(hCtrl, WM_GETFONT, 0, 0);
	if (hFont == NULL)
		goto out;
	SelectObject(hDC, hFont);
	len = GetWindowTextLengthW(hCtrl);
	if (len <= 0)
		goto out;
	wstr = calloc(len + 1, sizeof(wchar_t));
	if (wstr == NULL)
		goto out;
	if (GetWindowTextW(hCtrl, wstr, len + 1) > 0)
		GetTextExtentPoint32W(hDC, wstr, len, &sz);
out:
	safe_free(wstr);
	if (hDC != NULL)
		ReleaseDC(hCtrl, hDC);
	return sz;
}







LPCDLGTEMPLATE GetDialogTemplate(int Dialog_ID)
{
	int i;
	const char thai_id[] = "th-TH";
	size_t len;
	DWORD size;
	DWORD* dwBuf;
	WCHAR* wBuf;
	LPCDLGTEMPLATE rcTemplate = (LPCDLGTEMPLATE) GetResource(hMainInstance, MAKEINTRESOURCEA(Dialog_ID), _RT_DIALOG, get_name_from_id(Dialog_ID), &size, TRUE);

	if ((size == 0) || (rcTemplate == NULL)) {
		safe_free(rcTemplate);
		return NULL;
	}
	if (right_to_left_mode) {
		
		dwBuf = (DWORD*)rcTemplate;
		dwBuf[2] = WS_EX_RTLREADING | WS_EX_APPWINDOW | WS_EX_LAYOUTRTL;
	}

	
	
	
	

	
	if (IsFontAvailable("Segoe UI Symbol") && (selected_locale != NULL)
		&& (safe_strcmp(selected_locale->txt[0], thai_id) == 0))
		return rcTemplate;

	
	wBuf = (WCHAR*)rcTemplate;
	wBuf = &wBuf[14];	
	
	for (i = 0; i<2; i++) {
		if (*wBuf == 0xFFFF)
			wBuf = &wBuf[2];	
		else wBuf = &wBuf[wcslen(wBuf) + 1];
	}
	
	
	wBuf = &wBuf[3];
	
	if (wcscmp(L"Segoe UI Symbol", wBuf) == 0) {
		uintptr_t src, dst, start = (uintptr_t)rcTemplate;
		
		
		
		if ((nWindowsVersion > WINDOWS_XP) && IsFontAvailable("Segoe UI")) {
			
			wBuf[8] = 0;
		} else {
			wcscpy(wBuf, L"MS Shell Dlg");
		}
		len = wcslen(wBuf);
		wBuf[len + 1] = 0;
		dst = (uintptr_t)&wBuf[len + 2];
		dst &= ~3;
		src = (uintptr_t)&wBuf[17];
		src &= ~3;
		memmove((void*)dst, (void*)src, size - (src - start));
	} else {
		uprintf("Could not locate font for %s!", get_name_from_id(Dialog_ID));
	}
	return rcTemplate;
}

HWND MyCreateDialog(HINSTANCE hInstance, int Dialog_ID, HWND hWndParent, DLGPROC lpDialogFunc)
{
	LPCDLGTEMPLATE rcTemplate = GetDialogTemplate(Dialog_ID);
	HWND hDlg = CreateDialogIndirect(hInstance, rcTemplate, hWndParent, lpDialogFunc);
	safe_free(rcTemplate);
	return hDlg;
}

INT_PTR MyDialogBox(HINSTANCE hInstance, int Dialog_ID, HWND hWndParent, DLGPROC lpDialogFunc)
{
	INT_PTR ret;
	LPCDLGTEMPLATE rcTemplate = GetDialogTemplate(Dialog_ID);

	
	
	
	
	ShowWindow(hMainDialog, SW_NORMAL);

	ret = DialogBoxIndirect(hMainInstance, rcTemplate, hWndParent, lpDialogFunc);
	safe_free(rcTemplate);
	return ret;
}


static BOOL CALLBACK FormatPromptCallback(HWND hWnd, LPARAM lParam)
{
	char str[128];
	BOOL *found = (BOOL*)lParam;

	if (GetWindowTextU(hWnd, str, sizeof(str)) == 0)
		return TRUE;
	if (safe_strcmp(str, fp_button_str) == 0)
		*found = TRUE;
	return TRUE;
}

static void CALLBACK FormatPromptHook(HWINEVENTHOOK hWinEventHook, DWORD Event, HWND hWnd, LONG idObject, LONG idChild, DWORD dwEventThread, DWORD dwmsEventTime)
{
	char str[128];
	BOOL found;

	if (Event == EVENT_SYSTEM_FOREGROUND) {
		if (GetWindowLong(hWnd, GWL_STYLE) & WS_POPUPWINDOW) {
			str[0] = 0;
			GetWindowTextU(hWnd, str, sizeof(str));
			if (safe_strcmp(str, fp_title_str) == 0) {
				found = FALSE;
				EnumChildWindows(hWnd, FormatPromptCallback, (LPARAM)&found);
				if (found) {
					SendMessage(hWnd, WM_COMMAND, (WPARAM)IDCANCEL, (LPARAM)0);
					uprintf("Closed Windows format prompt");
				}
			}
		}
	}
}

BOOL SetFormatPromptHook(void)
{
	HMODULE mui_lib;
	char mui_path[MAX_PATH];
	static char title_str[128], button_str[128];

	if (fp_weh != NULL)
		return TRUE;	

						
	static_sprintf(mui_path, "%s\\%s\\shell32.dll.mui", system_dir, GetCurrentMUI());
	mui_lib = LoadLibraryU(mui_path);
	if (mui_lib != NULL) {
		
		
		
		if (LoadStringU(mui_lib, 4125, title_str, sizeof(title_str)) > 0)
			fp_title_str = title_str;
		else uprintf("Warning: Could not locate localized format prompt title string in '%s': %s", mui_path, WindowsErrorString());
		if (LoadStringU(mui_lib, 4126, button_str, sizeof(button_str)) > 0)
			fp_button_str = button_str;
		else uprintf("Warning: Could not locate localized format prompt button string in '%s': %s", mui_path, WindowsErrorString());
		FreeLibrary(mui_lib);
	}

	fp_weh = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, NULL, FormatPromptHook, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
	return (fp_weh != NULL);
}

void ClrFormatPromptHook(void) {
	UnhookWinEvent(fp_weh);
	fp_weh = NULL;
}

void FlashTaskbar(HANDLE handle)
{
	FLASHWINFO pf;

	if (handle == NULL)
		return;
	pf.cbSize = sizeof(FLASHWINFO);
	pf.hwnd = handle;
	
	pf.dwFlags = FLASHW_TIMER | FLASHW_TRAY;
	pf.uCount = 5;
	pf.dwTimeout = 75;
	FlashWindowEx(&pf);
}


static __inline LPWORD lpwAlign(LPWORD addr)
{
	return (LPWORD)((((uintptr_t)addr) + 3) & (~3));
}

INT_PTR CALLBACK SelectionDynCallback(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	int r = -1;
	switch (message) {
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDOK:
			r = 0;
		case IDCANCEL:
			EndDialog(hwndDlg, r);
			return (INT_PTR)TRUE;
		}
	}
	return FALSE;
}

int SelectionDyn(char* title, char* message, char** szChoice, int nChoices)
{

	LPCWSTR lpwszTypeFace = L"MS Shell Dlg";
	LPDLGTEMPLATEA lpdt;
	LPDLGITEMTEMPLATEA lpdit;
	LPCWSTR lpwszCaption;
	LPWORD lpw;
	LPWSTR lpwsz;
	int i, ret, nchar;

	lpdt = (LPDLGTEMPLATE)calloc(512 + nChoices * 256, 1);

	
	lpdt->style = WS_POPUP | WS_BORDER | WS_SYSMENU | WS_CAPTION | DS_MODALFRAME | DS_CENTER | DS_SHELLFONT;
	lpdt->cdit = 2 + nChoices;
	lpdt->x = 10;
	lpdt->y = 10;
	lpdt->cx = 300;
	lpdt->cy = 100;

	
	
	
	
	
	
	lpw = (LPWORD)(&lpdt[1]);
	*lpw++ = 0;		
	*lpw++ = 0;		
	lpwsz = (LPWSTR)lpw;
	nchar = MultiByteToWideChar(CP_UTF8, 0, title, -1, lpwsz, 50);
	lpw += nchar;

	
	if (lpdt->style & (DS_SETFONT | DS_SHELLFONT)) {
		*lpw++ = 8;
		for (lpwsz = (LPWSTR)lpw, lpwszCaption = lpwszTypeFace; (*lpwsz++ = *lpwszCaption++) != 0; );
		lpw = (LPWORD)lpwsz;
	}

	
	lpw = lpwAlign(lpw);
	lpdit = (LPDLGITEMTEMPLATE)lpw;
	lpdit->style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON;
	lpdit->x = 10;
	lpdit->y = 70;
	lpdit->cx = 50;
	lpdit->cy = 14;
	lpdit->id = IDOK;

	lpw = (LPWORD)(&lpdit[1]);
	*lpw++ = 0xFFFF;
	*lpw++ = 0x0080;	

	lpwsz = (LPWSTR)lpw;
	nchar = MultiByteToWideChar(CP_UTF8, 0, "OK", -1, lpwsz, 50);
	lpw += nchar;
	*lpw++ = 0;		

					
	lpw = lpwAlign(lpw);
	lpdit = (LPDLGITEMTEMPLATE)lpw;
	lpdit->x = 90;
	lpdit->y = 70;
	lpdit->cx = 50;
	lpdit->cy = 14;
	lpdit->id = IDCANCEL;
	lpdit->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON;

	lpw = (LPWORD)(&lpdit[1]);
	*lpw++ = 0xFFFF;
	*lpw++ = 0x0080;

	lpwsz = (LPWSTR)lpw;
	nchar = MultiByteToWideChar(CP_UTF8, 0, lmprintf(MSG_007), -1, lpwsz, 50);
	lpw += nchar;
	*lpw++ = 0;

	
	for (i = 0; i < nChoices; i++) {
		lpw = lpwAlign(lpw);
		lpdit = (LPDLGITEMTEMPLATE)lpw;
		lpdit->x = 10;
		lpdit->y = 10 + 15 * i;
		lpdit->cx = 40;
		lpdit->cy = 20;
		lpdit->id = ID_RADIO;
		lpdit->style = WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | (i == 0 ? WS_GROUP : 0);

		lpw = (LPWORD)(&lpdit[1]);
		*lpw++ = 0xFFFF;
		*lpw++ = 0x0080;

		lpwsz = (LPWSTR)lpw;
		nchar = MultiByteToWideChar(CP_UTF8, 0, szChoice[i], -1, lpwsz, 150);
		lpw += nchar;
		*lpw++ = 0;
	}

	ret = (int)DialogBoxIndirect(hMainInstance, (LPDLGTEMPLATE)lpdt, hMainDialog, (DLGPROC)SelectionDynCallback);
	free(lpdt);
	return ret;
}

