#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include "Asymmetric.h"
#include "Symmetric.h"
#include "Hash.h"
#include "Mac.h"
#include "Sign.h"
#include "Certificate.h"

#include <msclr\marshal_cppstd.h>
#include <typeinfo>
#include <string>
#include <locale>
#include <codecvt>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <windows.h>
#include <stdexcept>

#define BUFFER (2048)
#define ADD_LEN (32)

Asymmetric as;
Certificate cr;
Symmetric sm;
Sign sg;

namespace DEMOSSL {

	using namespace System;
	using namespace System::Text;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	public ref class Crypto : public System::Windows::Forms::Form
	{
	public:
		Crypto(void)
		{
			InitializeComponent();
		}
	protected:
		~Crypto()
		{
			if (components)
			{
				delete components;
			}
		}
	protected:
	private:
		/// <summary>
		/// Required designer variable.
		
		int ind_key = 0;
		int ind_ob = 0;
		int ind_rsa = 0;
		int ind_once = 0;
		int ind_rsasign = 0;
		int ind_ecsign = 0;
		int ind_sign = 0;
		int ind_ca = 0;
		int ind_req = 0;
		int ind_cert = 0;

		/// <summary>
	private: System::Windows::Forms::RichTextBox^ rtbInput;
	private: System::Windows::Forms::RichTextBox^ rtbOutput;
	private: System::Windows::Forms::Label^ lbOutput;
	private: System::Windows::Forms::GroupBox^ gbSymmetric;
	private: System::Windows::Forms::CheckBox^ cbPadding;
	private: System::Windows::Forms::RadioButton^ rbEcb;
	private: System::Windows::Forms::RadioButton^ rbCbc;
	private: System::Windows::Forms::Button^ btEncrypt;
	private: System::Windows::Forms::GroupBox^ gbHashMac;
	private: System::Windows::Forms::RadioButton^ rbCmac;
	private: System::Windows::Forms::RadioButton^ rbHmac;
	private: System::Windows::Forms::RadioButton^ rbSha512;
	private: System::Windows::Forms::RadioButton^ rbSha384;
	private: System::Windows::Forms::RadioButton^ rbSha256;
	private: System::Windows::Forms::RadioButton^ rbSha1;
	private: System::Windows::Forms::RadioButton^ rbMd5;
	private: System::Windows::Forms::Button^ btHash;
	private: System::Windows::Forms::Button^ btMac;
	private: System::Windows::Forms::RichTextBox^ rtbKey;
	private: System::Windows::Forms::Label^ lbKey;
	private: System::Windows::Forms::Button^ btClear;
	private: System::Windows::Forms::Button^ btEnterKey;
	private: System::Windows::Forms::Button^ btClearInput;
	private: System::Windows::Forms::Label^ lbKeyLentgh;
	private: System::Windows::Forms::Label^ lbKeyError;
	private: System::Windows::Forms::CheckBox^ cbHexKey;
	private: System::Windows::Forms::GroupBox^ gbCrypto;
	private: System::Windows::Forms::GroupBox^ gbSymMode;
	private: System::Windows::Forms::GroupBox^ gbSymAlgorithm;
	private: System::Windows::Forms::RadioButton^ rbRc4;
	private: System::Windows::Forms::RadioButton^ rbDes;
	private: System::Windows::Forms::RadioButton^ rbAes256;
	private: System::Windows::Forms::RadioButton^ rbTdes;
	private: System::Windows::Forms::RadioButton^ rbAes128;
	private: System::Windows::Forms::GroupBox^ gbAsymmetric;
	private: System::Windows::Forms::GroupBox^ gbAsymAlgorithm;
	private: System::Windows::Forms::RadioButton^ rbRsa;
	private: System::Windows::Forms::GroupBox^ gbMacMode;
	private: System::Windows::Forms::GroupBox^ gbMacAlgorithm;
	private: System::Windows::Forms::Button^ btGenerateRsa;
	private: System::Windows::Forms::GroupBox^ gbSymmetricKey;
	private: System::Windows::Forms::GroupBox^ gbIO;
	private: System::Windows::Forms::GroupBox^ gbPrivateKey;
	private: System::Windows::Forms::RichTextBox^ rtbPrivateKey;
	private: System::Windows::Forms::GroupBox^ tbPublicKey;
	private: System::Windows::Forms::RichTextBox^ rtbPublicKey;
	private: System::Windows::Forms::CheckBox^ cbShowPublicKey;
	private: System::Windows::Forms::CheckBox^ cbShowPrivateKey;
	private: System::Windows::Forms::GroupBox^ gbSign;
	private: System::Windows::Forms::GroupBox^ gbOutput;
	private: System::Windows::Forms::GroupBox^ gbInput;
	private: System::Windows::Forms::CheckBox^ cbUnlockOutput;
	private: System::Windows::Forms::CheckBox^ checkBox1;
	private: System::Windows::Forms::CheckBox^ checkBox2;
	private: System::Windows::Forms::Label^ lbReadFromFile;
	private: System::Windows::Forms::RichTextBox^ rtbReadPrivPubKey;
	private: System::Windows::Forms::Label^ lbRsaGenerated;
	private: System::Windows::Forms::Button^ btSignVerify;
	private: System::Windows::Forms::GroupBox^ gbAlgorithmSign;
	private: System::Windows::Forms::RadioButton^ rbRsaSign;
	private: System::Windows::Forms::RadioButton^ rbEcSign;
	private: System::Windows::Forms::Label^ lbSignKeys;
	private: System::Windows::Forms::Label^ lbEcKey;
	private: System::Windows::Forms::Label^ lbInputError;
	private: System::Windows::Forms::Label^ lbPublicKey;
	private: System::Windows::Forms::Label^ lbPrivateKey;
	private: System::Windows::Forms::CheckBox^ cbPublicKeyEc;
	private: System::Windows::Forms::CheckBox^ cbPrivateKeyEc;
	private: System::Windows::Forms::Label^ lbReafFromFileEc;
	private: System::Windows::Forms::Label^ lbOutAlg;
	private: System::Windows::Forms::Label^ lbElipticCurve;
	private: System::Windows::Forms::Panel^ pnEc;
	private: System::Windows::Forms::RadioButton^ rbEcBrainPool;
	private: System::Windows::Forms::RadioButton^ rbEcSecp;
	private: System::Windows::Forms::RadioButton^ rbEcDefault;
	private: System::Windows::Forms::Label^ label1;
	private: System::Windows::Forms::GroupBox^ gbCertificate;
	private: System::Windows::Forms::Button^ btGenRootCert;
	private: System::Windows::Forms::GroupBox^ gbCertAlg;
private: System::Windows::Forms::Label^ lbCAgen;

	private: System::Windows::Forms::Label^ lbCert;
	private: System::Windows::Forms::CheckBox^ cbReadCert;
	private: System::Windows::Forms::CheckBox^ cbReadCertReq;
	private: System::Windows::Forms::RadioButton^ rbCertRSA;
	private: System::Windows::Forms::CheckBox^ cbRootCA;
private: System::Windows::Forms::Label^ lbCertFromReq;

private: System::Windows::Forms::Label^ lbCertReq;

		/// </summary>
	System::ComponentModel::Container^ components;

#pragma region Windows Form Designer generated code
	/// <summary>
	/// Required method for Designer support - do not modify
	/// the contents of this method with the code editor.
	/// </summary>
	void InitializeComponent(void)
	{
		this->rtbInput = (gcnew System::Windows::Forms::RichTextBox());
		this->rtbOutput = (gcnew System::Windows::Forms::RichTextBox());
		this->lbOutput = (gcnew System::Windows::Forms::Label());
		this->gbSymmetric = (gcnew System::Windows::Forms::GroupBox());
		this->gbSymMode = (gcnew System::Windows::Forms::GroupBox());
		this->cbPadding = (gcnew System::Windows::Forms::CheckBox());
		this->rbCbc = (gcnew System::Windows::Forms::RadioButton());
		this->rbEcb = (gcnew System::Windows::Forms::RadioButton());
		this->btEncrypt = (gcnew System::Windows::Forms::Button());
		this->gbSymAlgorithm = (gcnew System::Windows::Forms::GroupBox());
		this->rbRc4 = (gcnew System::Windows::Forms::RadioButton());
		this->rbDes = (gcnew System::Windows::Forms::RadioButton());
		this->rbAes256 = (gcnew System::Windows::Forms::RadioButton());
		this->rbTdes = (gcnew System::Windows::Forms::RadioButton());
		this->rbAes128 = (gcnew System::Windows::Forms::RadioButton());
		this->cbHexKey = (gcnew System::Windows::Forms::CheckBox());
		this->lbKeyError = (gcnew System::Windows::Forms::Label());
		this->lbKeyLentgh = (gcnew System::Windows::Forms::Label());
		this->rtbKey = (gcnew System::Windows::Forms::RichTextBox());
		this->btClearInput = (gcnew System::Windows::Forms::Button());
		this->btEnterKey = (gcnew System::Windows::Forms::Button());
		this->btClear = (gcnew System::Windows::Forms::Button());
		this->lbKey = (gcnew System::Windows::Forms::Label());
		this->gbHashMac = (gcnew System::Windows::Forms::GroupBox());
		this->gbMacMode = (gcnew System::Windows::Forms::GroupBox());
		this->rbCmac = (gcnew System::Windows::Forms::RadioButton());
		this->rbHmac = (gcnew System::Windows::Forms::RadioButton());
		this->btHash = (gcnew System::Windows::Forms::Button());
		this->gbMacAlgorithm = (gcnew System::Windows::Forms::GroupBox());
		this->rbSha512 = (gcnew System::Windows::Forms::RadioButton());
		this->rbMd5 = (gcnew System::Windows::Forms::RadioButton());
		this->rbSha384 = (gcnew System::Windows::Forms::RadioButton());
		this->rbSha1 = (gcnew System::Windows::Forms::RadioButton());
		this->rbSha256 = (gcnew System::Windows::Forms::RadioButton());
		this->btMac = (gcnew System::Windows::Forms::Button());
		this->rtbReadPrivPubKey = (gcnew System::Windows::Forms::RichTextBox());
		this->gbCrypto = (gcnew System::Windows::Forms::GroupBox());
		this->gbCertificate = (gcnew System::Windows::Forms::GroupBox());
		this->btGenRootCert = (gcnew System::Windows::Forms::Button());
		this->gbCertAlg = (gcnew System::Windows::Forms::GroupBox());
		this->lbCertFromReq = (gcnew System::Windows::Forms::Label());
		this->lbCertReq = (gcnew System::Windows::Forms::Label());
		this->cbRootCA = (gcnew System::Windows::Forms::CheckBox());
		this->lbCAgen = (gcnew System::Windows::Forms::Label());
		this->lbCert = (gcnew System::Windows::Forms::Label());
		this->cbReadCert = (gcnew System::Windows::Forms::CheckBox());
		this->cbReadCertReq = (gcnew System::Windows::Forms::CheckBox());
		this->rbCertRSA = (gcnew System::Windows::Forms::RadioButton());
		this->gbSign = (gcnew System::Windows::Forms::GroupBox());
		this->btSignVerify = (gcnew System::Windows::Forms::Button());
		this->gbAlgorithmSign = (gcnew System::Windows::Forms::GroupBox());
		this->label1 = (gcnew System::Windows::Forms::Label());
		this->pnEc = (gcnew System::Windows::Forms::Panel());
		this->rbEcDefault = (gcnew System::Windows::Forms::RadioButton());
		this->lbElipticCurve = (gcnew System::Windows::Forms::Label());
		this->rbEcSecp = (gcnew System::Windows::Forms::RadioButton());
		this->rbEcBrainPool = (gcnew System::Windows::Forms::RadioButton());
		this->lbSignKeys = (gcnew System::Windows::Forms::Label());
		this->lbEcKey = (gcnew System::Windows::Forms::Label());
		this->rbRsaSign = (gcnew System::Windows::Forms::RadioButton());
		this->cbPublicKeyEc = (gcnew System::Windows::Forms::CheckBox());
		this->cbPrivateKeyEc = (gcnew System::Windows::Forms::CheckBox());
		this->lbReafFromFileEc = (gcnew System::Windows::Forms::Label());
		this->rbEcSign = (gcnew System::Windows::Forms::RadioButton());
		this->gbIO = (gcnew System::Windows::Forms::GroupBox());
		this->gbOutput = (gcnew System::Windows::Forms::GroupBox());
		this->lbOutAlg = (gcnew System::Windows::Forms::Label());
		this->cbUnlockOutput = (gcnew System::Windows::Forms::CheckBox());
		this->gbInput = (gcnew System::Windows::Forms::GroupBox());
		this->lbInputError = (gcnew System::Windows::Forms::Label());
		this->gbSymmetricKey = (gcnew System::Windows::Forms::GroupBox());
		this->tbPublicKey = (gcnew System::Windows::Forms::GroupBox());
		this->lbPublicKey = (gcnew System::Windows::Forms::Label());
		this->checkBox1 = (gcnew System::Windows::Forms::CheckBox());
		this->rtbPublicKey = (gcnew System::Windows::Forms::RichTextBox());
		this->gbPrivateKey = (gcnew System::Windows::Forms::GroupBox());
		this->lbPrivateKey = (gcnew System::Windows::Forms::Label());
		this->checkBox2 = (gcnew System::Windows::Forms::CheckBox());
		this->rtbPrivateKey = (gcnew System::Windows::Forms::RichTextBox());
		this->gbAsymmetric = (gcnew System::Windows::Forms::GroupBox());
		this->btGenerateRsa = (gcnew System::Windows::Forms::Button());
		this->gbAsymAlgorithm = (gcnew System::Windows::Forms::GroupBox());
		this->lbRsaGenerated = (gcnew System::Windows::Forms::Label());
		this->lbReadFromFile = (gcnew System::Windows::Forms::Label());
		this->cbShowPublicKey = (gcnew System::Windows::Forms::CheckBox());
		this->cbShowPrivateKey = (gcnew System::Windows::Forms::CheckBox());
		this->rbRsa = (gcnew System::Windows::Forms::RadioButton());
		this->gbSymmetric->SuspendLayout();
		this->gbSymMode->SuspendLayout();
		this->gbSymAlgorithm->SuspendLayout();
		this->gbHashMac->SuspendLayout();
		this->gbMacMode->SuspendLayout();
		this->gbMacAlgorithm->SuspendLayout();
		this->gbCrypto->SuspendLayout();
		this->gbCertificate->SuspendLayout();
		this->gbCertAlg->SuspendLayout();
		this->gbSign->SuspendLayout();
		this->gbAlgorithmSign->SuspendLayout();
		this->pnEc->SuspendLayout();
		this->gbIO->SuspendLayout();
		this->gbOutput->SuspendLayout();
		this->gbInput->SuspendLayout();
		this->gbSymmetricKey->SuspendLayout();
		this->tbPublicKey->SuspendLayout();
		this->gbPrivateKey->SuspendLayout();
		this->gbAsymmetric->SuspendLayout();
		this->gbAsymAlgorithm->SuspendLayout();
		this->SuspendLayout();
		// 
		// rtbInput
		// 
		this->rtbInput->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->rtbInput->Location = System::Drawing::Point(15, 22);
		this->rtbInput->Name = L"rtbInput";
		this->rtbInput->Size = System::Drawing::Size(612, 85);
		this->rtbInput->TabIndex = 0;
		this->rtbInput->Text = L"";
		// 
		// rtbOutput
		// 
		this->rtbOutput->Enabled = false;
		this->rtbOutput->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->rtbOutput->Location = System::Drawing::Point(16, 22);
		this->rtbOutput->Name = L"rtbOutput";
		this->rtbOutput->Size = System::Drawing::Size(478, 152);
		this->rtbOutput->TabIndex = 1;
		this->rtbOutput->Text = L"";
		// 
		// lbOutput
		// 
		this->lbOutput->AutoSize = true;
		this->lbOutput->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->lbOutput->Location = System::Drawing::Point(23, 178);
		this->lbOutput->Name = L"lbOutput";
		this->lbOutput->Size = System::Drawing::Size(0, 17);
		this->lbOutput->TabIndex = 5;
		// 
		// gbSymmetric
		// 
		this->gbSymmetric->Controls->Add(this->gbSymMode);
		this->gbSymmetric->Controls->Add(this->btEncrypt);
		this->gbSymmetric->Controls->Add(this->gbSymAlgorithm);
		this->gbSymmetric->Location = System::Drawing::Point(17, 143);
		this->gbSymmetric->Name = L"gbSymmetric";
		this->gbSymmetric->Size = System::Drawing::Size(681, 164);
		this->gbSymmetric->TabIndex = 6;
		this->gbSymmetric->TabStop = false;
		this->gbSymmetric->Text = L"Symmetric encryption";
		// 
		// gbSymMode
		// 
		this->gbSymMode->Controls->Add(this->cbPadding);
		this->gbSymMode->Controls->Add(this->rbCbc);
		this->gbSymMode->Controls->Add(this->rbEcb);
		this->gbSymMode->Location = System::Drawing::Point(18, 92);
		this->gbSymMode->Name = L"gbSymMode";
		this->gbSymMode->Size = System::Drawing::Size(506, 59);
		this->gbSymMode->TabIndex = 17;
		this->gbSymMode->TabStop = false;
		this->gbSymMode->Text = L"Mode";
		// 
		// cbPadding
		// 
		this->cbPadding->AutoSize = true;
		this->cbPadding->Location = System::Drawing::Point(187, 33);
		this->cbPadding->Name = L"cbPadding";
		this->cbPadding->Size = System::Drawing::Size(110, 21);
		this->cbPadding->TabIndex = 8;
		this->cbPadding->Text = L"No padding";
		this->cbPadding->UseVisualStyleBackColor = true;
		// 
		// rbCbc
		// 
		this->rbCbc->AutoSize = true;
		this->rbCbc->Checked = true;
		this->rbCbc->Location = System::Drawing::Point(22, 32);
		this->rbCbc->Name = L"rbCbc";
		this->rbCbc->Size = System::Drawing::Size(56, 21);
		this->rbCbc->TabIndex = 6;
		this->rbCbc->TabStop = true;
		this->rbCbc->Text = L"CBC";
		this->rbCbc->UseVisualStyleBackColor = true;
		// 
		// rbEcb
		// 
		this->rbEcb->AutoSize = true;
		this->rbEcb->Location = System::Drawing::Point(94, 32);
		this->rbEcb->Name = L"rbEcb";
		this->rbEcb->Size = System::Drawing::Size(56, 21);
		this->rbEcb->TabIndex = 7;
		this->rbEcb->Text = L"EBC";
		this->rbEcb->UseVisualStyleBackColor = true;
		// 
		// btEncrypt
		// 
		this->btEncrypt->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 10, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->btEncrypt->Location = System::Drawing::Point(548, 32);
		this->btEncrypt->Name = L"btEncrypt";
		this->btEncrypt->Size = System::Drawing::Size(116, 119);
		this->btEncrypt->TabIndex = 2;
		this->btEncrypt->Text = L"ENCRYPT";
		this->btEncrypt->UseVisualStyleBackColor = true;
		this->btEncrypt->Click += gcnew System::EventHandler(this, &Crypto::btEncrypt_Click);
		// 
		// gbSymAlgorithm
		// 
		this->gbSymAlgorithm->Controls->Add(this->rbRc4);
		this->gbSymAlgorithm->Controls->Add(this->rbDes);
		this->gbSymAlgorithm->Controls->Add(this->rbAes256);
		this->gbSymAlgorithm->Controls->Add(this->rbTdes);
		this->gbSymAlgorithm->Controls->Add(this->rbAes128);
		this->gbSymAlgorithm->Location = System::Drawing::Point(18, 22);
		this->gbSymAlgorithm->Name = L"gbSymAlgorithm";
		this->gbSymAlgorithm->Size = System::Drawing::Size(506, 64);
		this->gbSymAlgorithm->TabIndex = 16;
		this->gbSymAlgorithm->TabStop = false;
		this->gbSymAlgorithm->Text = L"Algorithm";
		// 
		// rbRc4
		// 
		this->rbRc4->AutoSize = true;
		this->rbRc4->Location = System::Drawing::Point(414, 33);
		this->rbRc4->Name = L"rbRc4";
		this->rbRc4->Size = System::Drawing::Size(56, 21);
		this->rbRc4->TabIndex = 21;
		this->rbRc4->TabStop = true;
		this->rbRc4->Text = L"RC4";
		this->rbRc4->UseVisualStyleBackColor = true;
		this->rbRc4->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbRc4_CheckedChanged);
		// 
		// rbDes
		// 
		this->rbDes->AutoSize = true;
		this->rbDes->Checked = true;
		this->rbDes->Location = System::Drawing::Point(22, 33);
		this->rbDes->Name = L"rbDes";
		this->rbDes->Size = System::Drawing::Size(57, 21);
		this->rbDes->TabIndex = 17;
		this->rbDes->TabStop = true;
		this->rbDes->Text = L"DES";
		this->rbDes->UseVisualStyleBackColor = true;
		this->rbDes->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbDes_CheckedChanged);
		// 
		// rbAes256
		// 
		this->rbAes256->AutoSize = true;
		this->rbAes256->Location = System::Drawing::Point(302, 33);
		this->rbAes256->Name = L"rbAes256";
		this->rbAes256->Size = System::Drawing::Size(88, 21);
		this->rbAes256->TabIndex = 20;
		this->rbAes256->TabStop = true;
		this->rbAes256->Text = L"AES 256";
		this->rbAes256->UseVisualStyleBackColor = true;
		this->rbAes256->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbAes256_CheckedChanged);
		// 
		// rbTdes
		// 
		this->rbTdes->AutoSize = true;
		this->rbTdes->Location = System::Drawing::Point(95, 33);
		this->rbTdes->Name = L"rbTdes";
		this->rbTdes->Size = System::Drawing::Size(67, 21);
		this->rbTdes->TabIndex = 18;
		this->rbTdes->TabStop = true;
		this->rbTdes->Text = L"TDES";
		this->rbTdes->UseVisualStyleBackColor = true;
		this->rbTdes->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbTdes_CheckedChanged);
		// 
		// rbAes128
		// 
		this->rbAes128->AutoSize = true;
		this->rbAes128->Location = System::Drawing::Point(187, 33);
		this->rbAes128->Name = L"rbAes128";
		this->rbAes128->Size = System::Drawing::Size(88, 21);
		this->rbAes128->TabIndex = 19;
		this->rbAes128->TabStop = true;
		this->rbAes128->Text = L"AES 128";
		this->rbAes128->UseVisualStyleBackColor = true;
		this->rbAes128->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbAes128_CheckedChanged);
		// 
		// cbHexKey
		// 
		this->cbHexKey->AutoSize = true;
		this->cbHexKey->Checked = true;
		this->cbHexKey->CheckState = System::Windows::Forms::CheckState::Checked;
		this->cbHexKey->Location = System::Drawing::Point(25, 89);
		this->cbHexKey->Name = L"cbHexKey";
		this->cbHexKey->Size = System::Drawing::Size(96, 21);
		this->cbHexKey->TabIndex = 15;
		this->cbHexKey->Text = L"hex value";
		this->cbHexKey->UseVisualStyleBackColor = true;
		this->cbHexKey->CheckedChanged += gcnew System::EventHandler(this, &Crypto::cbHexKey_CheckedChanged);
		// 
		// lbKeyError
		// 
		this->lbKeyError->AutoSize = true;
		this->lbKeyError->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 10, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->lbKeyError->ForeColor = System::Drawing::Color::Red;
		this->lbKeyError->Location = System::Drawing::Point(151, 89);
		this->lbKeyError->Name = L"lbKeyError";
		this->lbKeyError->Size = System::Drawing::Size(0, 17);
		this->lbKeyError->TabIndex = 14;
		// 
		// lbKeyLentgh
		// 
		this->lbKeyLentgh->AutoSize = true;
		this->lbKeyLentgh->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->lbKeyLentgh->Location = System::Drawing::Point(351, 88);
		this->lbKeyLentgh->Name = L"lbKeyLentgh";
		this->lbKeyLentgh->Size = System::Drawing::Size(143, 17);
		this->lbKeyLentgh->TabIndex = 13;
		this->lbKeyLentgh->Text = L"Key length 8 bytes";
		// 
		// rtbKey
		// 
		this->rtbKey->Enabled = false;
		this->rtbKey->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->rtbKey->Location = System::Drawing::Point(15, 23);
		this->rtbKey->Name = L"rtbKey";
		this->rtbKey->Size = System::Drawing::Size(479, 63);
		this->rtbKey->TabIndex = 8;
		this->rtbKey->Text = L"";
		// 
		// btClearInput
		// 
		this->btClearInput->Location = System::Drawing::Point(515, 22);
		this->btClearInput->Name = L"btClearInput";
		this->btClearInput->Size = System::Drawing::Size(112, 69);
		this->btClearInput->TabIndex = 12;
		this->btClearInput->Text = L"CLEAR \r\nIN - OUT";
		this->btClearInput->UseVisualStyleBackColor = true;
		this->btClearInput->Click += gcnew System::EventHandler(this, &Crypto::btClearInput_Click);
		// 
		// btEnterKey
		// 
		this->btEnterKey->Location = System::Drawing::Point(515, 23);
		this->btEnterKey->Name = L"btEnterKey";
		this->btEnterKey->Size = System::Drawing::Size(112, 63);
		this->btEnterKey->TabIndex = 11;
		this->btEnterKey->Text = L"ENTER KEY";
		this->btEnterKey->UseVisualStyleBackColor = true;
		this->btEnterKey->Click += gcnew System::EventHandler(this, &Crypto::btEnterKey_Click);
		// 
		// btClear
		// 
		this->btClear->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 10, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->btClear->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->btClear->Location = System::Drawing::Point(515, 109);
		this->btClear->Name = L"btClear";
		this->btClear->Size = System::Drawing::Size(112, 65);
		this->btClear->TabIndex = 10;
		this->btClear->Text = L"RESET ALL";
		this->btClear->UseVisualStyleBackColor = true;
		this->btClear->Click += gcnew System::EventHandler(this, &Crypto::btClear_Click);
		// 
		// lbKey
		// 
		this->lbKey->AutoSize = true;
		this->lbKey->Location = System::Drawing::Point(12, 23);
		this->lbKey->Name = L"lbKey";
		this->lbKey->Size = System::Drawing::Size(0, 17);
		this->lbKey->TabIndex = 9;
		// 
		// gbHashMac
		// 
		this->gbHashMac->Controls->Add(this->gbMacMode);
		this->gbHashMac->Controls->Add(this->btHash);
		this->gbHashMac->Controls->Add(this->gbMacAlgorithm);
		this->gbHashMac->Controls->Add(this->btMac);
		this->gbHashMac->Location = System::Drawing::Point(17, 313);
		this->gbHashMac->Name = L"gbHashMac";
		this->gbHashMac->Size = System::Drawing::Size(681, 166);
		this->gbHashMac->TabIndex = 7;
		this->gbHashMac->TabStop = false;
		this->gbHashMac->Text = L"Hash - Mac";
		// 
		// gbMacMode
		// 
		this->gbMacMode->Controls->Add(this->rbCmac);
		this->gbMacMode->Controls->Add(this->rbHmac);
		this->gbMacMode->Location = System::Drawing::Point(18, 92);
		this->gbMacMode->Name = L"gbMacMode";
		this->gbMacMode->Size = System::Drawing::Size(506, 61);
		this->gbMacMode->TabIndex = 18;
		this->gbMacMode->TabStop = false;
		this->gbMacMode->Text = L"Mode";
		// 
		// rbCmac
		// 
		this->rbCmac->AutoSize = true;
		this->rbCmac->Location = System::Drawing::Point(94, 34);
		this->rbCmac->Name = L"rbCmac";
		this->rbCmac->Size = System::Drawing::Size(68, 21);
		this->rbCmac->TabIndex = 7;
		this->rbCmac->TabStop = true;
		this->rbCmac->Text = L"CMAC";
		this->rbCmac->UseVisualStyleBackColor = true;
		this->rbCmac->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbCmac_CheckedChanged);
		// 
		// rbHmac
		// 
		this->rbHmac->AutoSize = true;
		this->rbHmac->Checked = true;
		this->rbHmac->Location = System::Drawing::Point(22, 34);
		this->rbHmac->Name = L"rbHmac";
		this->rbHmac->Size = System::Drawing::Size(69, 21);
		this->rbHmac->TabIndex = 6;
		this->rbHmac->TabStop = true;
		this->rbHmac->Text = L"HMAC";
		this->rbHmac->UseVisualStyleBackColor = true;
		this->rbHmac->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbHmac_CheckedChanged);
		// 
		// btHash
		// 
		this->btHash->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 10, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->btHash->Location = System::Drawing::Point(548, 31);
		this->btHash->Name = L"btHash";
		this->btHash->Size = System::Drawing::Size(116, 55);
		this->btHash->TabIndex = 2;
		this->btHash->Text = L"HASH";
		this->btHash->UseVisualStyleBackColor = true;
		this->btHash->Click += gcnew System::EventHandler(this, &Crypto::btHash_Click);
		// 
		// gbMacAlgorithm
		// 
		this->gbMacAlgorithm->Controls->Add(this->rbSha512);
		this->gbMacAlgorithm->Controls->Add(this->rbMd5);
		this->gbMacAlgorithm->Controls->Add(this->rbSha384);
		this->gbMacAlgorithm->Controls->Add(this->rbSha1);
		this->gbMacAlgorithm->Controls->Add(this->rbSha256);
		this->gbMacAlgorithm->Location = System::Drawing::Point(18, 22);
		this->gbMacAlgorithm->Name = L"gbMacAlgorithm";
		this->gbMacAlgorithm->Size = System::Drawing::Size(506, 64);
		this->gbMacAlgorithm->TabIndex = 22;
		this->gbMacAlgorithm->TabStop = false;
		this->gbMacAlgorithm->Text = L"Algorithm";
		// 
		// rbSha512
		// 
		this->rbSha512->AutoSize = true;
		this->rbSha512->Location = System::Drawing::Point(414, 32);
		this->rbSha512->Name = L"rbSha512";
		this->rbSha512->Size = System::Drawing::Size(89, 21);
		this->rbSha512->TabIndex = 4;
		this->rbSha512->TabStop = true;
		this->rbSha512->Text = L"SHA 512";
		this->rbSha512->UseVisualStyleBackColor = true;
		this->rbSha512->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbSha512_CheckedChanged);
		// 
		// rbMd5
		// 
		this->rbMd5->AutoSize = true;
		this->rbMd5->Checked = true;
		this->rbMd5->Location = System::Drawing::Point(22, 32);
		this->rbMd5->Name = L"rbMd5";
		this->rbMd5->Size = System::Drawing::Size(58, 21);
		this->rbMd5->TabIndex = 0;
		this->rbMd5->TabStop = true;
		this->rbMd5->Text = L"MD5";
		this->rbMd5->UseVisualStyleBackColor = true;
		this->rbMd5->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbMd5_CheckedChanged);
		// 
		// rbSha384
		// 
		this->rbSha384->AutoSize = true;
		this->rbSha384->Location = System::Drawing::Point(302, 32);
		this->rbSha384->Name = L"rbSha384";
		this->rbSha384->Size = System::Drawing::Size(89, 21);
		this->rbSha384->TabIndex = 3;
		this->rbSha384->TabStop = true;
		this->rbSha384->Text = L"SHA 384";
		this->rbSha384->UseVisualStyleBackColor = true;
		this->rbSha384->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbSha384_CheckedChanged);
		// 
		// rbSha1
		// 
		this->rbSha1->AutoSize = true;
		this->rbSha1->Location = System::Drawing::Point(95, 32);
		this->rbSha1->Name = L"rbSha1";
		this->rbSha1->Size = System::Drawing::Size(71, 21);
		this->rbSha1->TabIndex = 1;
		this->rbSha1->TabStop = true;
		this->rbSha1->Text = L"SHA 1";
		this->rbSha1->UseVisualStyleBackColor = true;
		this->rbSha1->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbSha1_CheckedChanged);
		// 
		// rbSha256
		// 
		this->rbSha256->AutoSize = true;
		this->rbSha256->Location = System::Drawing::Point(187, 32);
		this->rbSha256->Name = L"rbSha256";
		this->rbSha256->Size = System::Drawing::Size(89, 21);
		this->rbSha256->TabIndex = 2;
		this->rbSha256->TabStop = true;
		this->rbSha256->Text = L"SHA 256";
		this->rbSha256->UseVisualStyleBackColor = true;
		this->rbSha256->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbSha256_CheckedChanged);
		// 
		// btMac
		// 
		this->btMac->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 10, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->btMac->Location = System::Drawing::Point(548, 97);
		this->btMac->Name = L"btMac";
		this->btMac->Size = System::Drawing::Size(116, 56);
		this->btMac->TabIndex = 3;
		this->btMac->Text = L"MAC";
		this->btMac->UseVisualStyleBackColor = true;
		this->btMac->Click += gcnew System::EventHandler(this, &Crypto::btMac_Click);
		// 
		// rtbReadPrivPubKey
		// 
		this->rtbReadPrivPubKey->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->rtbReadPrivPubKey->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->rtbReadPrivPubKey->Location = System::Drawing::Point(775, 29);
		this->rtbReadPrivPubKey->Name = L"rtbReadPrivPubKey";
		this->rtbReadPrivPubKey->ReadOnly = true;
		this->rtbReadPrivPubKey->Size = System::Drawing::Size(706, 559);
		this->rtbReadPrivPubKey->TabIndex = 19;
		this->rtbReadPrivPubKey->Text = L"";
		this->rtbReadPrivPubKey->Visible = false;
		// 
		// gbCrypto
		// 
		this->gbCrypto->Controls->Add(this->gbCertificate);
		this->gbCrypto->Controls->Add(this->gbSign);
		this->gbCrypto->Controls->Add(this->gbIO);
		this->gbCrypto->Controls->Add(this->gbAsymmetric);
		this->gbCrypto->Controls->Add(this->gbSymmetric);
		this->gbCrypto->Controls->Add(this->gbHashMac);
		this->gbCrypto->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 10, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->gbCrypto->Location = System::Drawing::Point(34, 12);
		this->gbCrypto->Name = L"gbCrypto";
		this->gbCrypto->Size = System::Drawing::Size(1447, 820);
		this->gbCrypto->TabIndex = 4;
		this->gbCrypto->TabStop = false;
		this->gbCrypto->Text = L"Crypto";
		// 
		// gbCertificate
		// 
		this->gbCertificate->Controls->Add(this->btGenRootCert);
		this->gbCertificate->Controls->Add(this->gbCertAlg);
		this->gbCertificate->Location = System::Drawing::Point(17, 679);
		this->gbCertificate->Name = L"gbCertificate";
		this->gbCertificate->Size = System::Drawing::Size(681, 127);
		this->gbCertificate->TabIndex = 23;
		this->gbCertificate->TabStop = false;
		this->gbCertificate->Text = L"Certificate";
		// 
		// btGenRootCert
		// 
		this->btGenRootCert->Location = System::Drawing::Point(548, 30);
		this->btGenRootCert->Name = L"btGenRootCert";
		this->btGenRootCert->Size = System::Drawing::Size(116, 74);
		this->btGenRootCert->TabIndex = 17;
		this->btGenRootCert->Text = L"GENERATE ROOT CA";
		this->btGenRootCert->UseVisualStyleBackColor = true;
		this->btGenRootCert->Click += gcnew System::EventHandler(this, &Crypto::btGenRootCert_Click);
		// 
		// gbCertAlg
		// 
		this->gbCertAlg->Controls->Add(this->lbCertFromReq);
		this->gbCertAlg->Controls->Add(this->lbCertReq);
		this->gbCertAlg->Controls->Add(this->cbRootCA);
		this->gbCertAlg->Controls->Add(this->lbCAgen);
		this->gbCertAlg->Controls->Add(this->lbCert);
		this->gbCertAlg->Controls->Add(this->cbReadCert);
		this->gbCertAlg->Controls->Add(this->cbReadCertReq);
		this->gbCertAlg->Controls->Add(this->rbCertRSA);
		this->gbCertAlg->Location = System::Drawing::Point(18, 22);
		this->gbCertAlg->Name = L"gbCertAlg";
		this->gbCertAlg->Size = System::Drawing::Size(506, 82);
		this->gbCertAlg->TabIndex = 22;
		this->gbCertAlg->TabStop = false;
		this->gbCertAlg->Text = L"Algorithm";
		// 
		// lbCertFromReq
		// 
		this->lbCertFromReq->AutoSize = true;
		this->lbCertFromReq->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->lbCertFromReq->Location = System::Drawing::Point(418, 57);
		this->lbCertFromReq->Name = L"lbCertFromReq";
		this->lbCertFromReq->Size = System::Drawing::Size(85, 17);
		this->lbCertFromReq->TabIndex = 25;
		this->lbCertFromReq->Text = L"Generated";
		this->lbCertFromReq->TextAlign = System::Drawing::ContentAlignment::TopCenter;
		this->lbCertFromReq->Visible = false;
		// 
		// lbCertReq
		// 
		this->lbCertReq->AutoSize = true;
		this->lbCertReq->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->lbCertReq->Location = System::Drawing::Point(418, 35);
		this->lbCertReq->Name = L"lbCertReq";
		this->lbCertReq->Size = System::Drawing::Size(85, 17);
		this->lbCertReq->TabIndex = 24;
		this->lbCertReq->Text = L"Generated";
		this->lbCertReq->TextAlign = System::Drawing::ContentAlignment::TopCenter;
		this->lbCertReq->Visible = false;
		// 
		// cbRootCA
		// 
		this->cbRootCA->AutoSize = true;
		this->cbRootCA->Enabled = false;
		this->cbRootCA->Location = System::Drawing::Point(216, 13);
		this->cbRootCA->Name = L"cbRootCA";
		this->cbRootCA->Size = System::Drawing::Size(86, 21);
		this->cbRootCA->TabIndex = 23;
		this->cbRootCA->Text = L"Root CA";
		this->cbRootCA->UseVisualStyleBackColor = true;
		this->cbRootCA->CheckedChanged += gcnew System::EventHandler(this, &Crypto::cbRootCA_CheckedChanged);
		// 
		// lbCAgen
		// 
		this->lbCAgen->AutoSize = true;
		this->lbCAgen->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->lbCAgen->Location = System::Drawing::Point(418, 14);
		this->lbCAgen->Name = L"lbCAgen";
		this->lbCAgen->Size = System::Drawing::Size(85, 17);
		this->lbCAgen->TabIndex = 22;
		this->lbCAgen->Text = L"Generated";
		this->lbCAgen->TextAlign = System::Drawing::ContentAlignment::TopCenter;
		this->lbCAgen->Visible = false;
		// 
		// lbCert
		// 
		this->lbCert->AutoSize = true;
		this->lbCert->Location = System::Drawing::Point(109, 26);
		this->lbCert->Name = L"lbCert";
		this->lbCert->Size = System::Drawing::Size(101, 34);
		this->lbCert->TabIndex = 21;
		this->lbCert->Text = L"READ CERT \r\nfrom file:";
		this->lbCert->TextAlign = System::Drawing::ContentAlignment::MiddleCenter;
		// 
		// cbReadCert
		// 
		this->cbReadCert->AutoSize = true;
		this->cbReadCert->Enabled = false;
		this->cbReadCert->Location = System::Drawing::Point(216, 57);
		this->cbReadCert->Name = L"cbReadCert";
		this->cbReadCert->Size = System::Drawing::Size(203, 21);
		this->cbReadCert->TabIndex = 20;
		this->cbReadCert->Text = L"Certificate from Request";
		this->cbReadCert->UseVisualStyleBackColor = true;
		this->cbReadCert->CheckedChanged += gcnew System::EventHandler(this, &Crypto::cbReadCert_CheckedChanged);
		// 
		// cbReadCertReq
		// 
		this->cbReadCertReq->AutoSize = true;
		this->cbReadCertReq->Enabled = false;
		this->cbReadCertReq->Location = System::Drawing::Point(216, 34);
		this->cbReadCertReq->Name = L"cbReadCertReq";
		this->cbReadCertReq->Size = System::Drawing::Size(166, 21);
		this->cbReadCertReq->TabIndex = 19;
		this->cbReadCertReq->Text = L"Certificate Request";
		this->cbReadCertReq->UseVisualStyleBackColor = true;
		this->cbReadCertReq->CheckedChanged += gcnew System::EventHandler(this, &Crypto::cbReadCertReq_CheckedChanged);
		// 
		// rbCertRSA
		// 
		this->rbCertRSA->AutoSize = true;
		this->rbCertRSA->Checked = true;
		this->rbCertRSA->Location = System::Drawing::Point(22, 33);
		this->rbCertRSA->Name = L"rbCertRSA";
		this->rbCertRSA->Size = System::Drawing::Size(57, 21);
		this->rbCertRSA->TabIndex = 17;
		this->rbCertRSA->TabStop = true;
		this->rbCertRSA->Text = L"RSA";
		this->rbCertRSA->UseVisualStyleBackColor = true;
		// 
		// gbSign
		// 
		this->gbSign->Controls->Add(this->btSignVerify);
		this->gbSign->Controls->Add(this->gbAlgorithmSign);
		this->gbSign->Location = System::Drawing::Point(17, 485);
		this->gbSign->Name = L"gbSign";
		this->gbSign->Size = System::Drawing::Size(681, 188);
		this->gbSign->TabIndex = 18;
		this->gbSign->TabStop = false;
		this->gbSign->Text = L"Digital sign";
		this->gbSign->Enter += gcnew System::EventHandler(this, &Crypto::gbSign_Enter);
		// 
		// btSignVerify
		// 
		this->btSignVerify->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 10, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->btSignVerify->Location = System::Drawing::Point(548, 32);
		this->btSignVerify->Name = L"btSignVerify";
		this->btSignVerify->Size = System::Drawing::Size(116, 145);
		this->btSignVerify->TabIndex = 23;
		this->btSignVerify->Text = L"GENERATE\r\nEC KEYS";
		this->btSignVerify->UseVisualStyleBackColor = true;
		this->btSignVerify->Click += gcnew System::EventHandler(this, &Crypto::btSignVerify_Click);
		// 
		// gbAlgorithmSign
		// 
		this->gbAlgorithmSign->Controls->Add(this->label1);
		this->gbAlgorithmSign->Controls->Add(this->pnEc);
		this->gbAlgorithmSign->Controls->Add(this->lbSignKeys);
		this->gbAlgorithmSign->Controls->Add(this->lbEcKey);
		this->gbAlgorithmSign->Controls->Add(this->rbRsaSign);
		this->gbAlgorithmSign->Controls->Add(this->cbPublicKeyEc);
		this->gbAlgorithmSign->Controls->Add(this->cbPrivateKeyEc);
		this->gbAlgorithmSign->Controls->Add(this->lbReafFromFileEc);
		this->gbAlgorithmSign->Controls->Add(this->rbEcSign);
		this->gbAlgorithmSign->Location = System::Drawing::Point(18, 22);
		this->gbAlgorithmSign->Name = L"gbAlgorithmSign";
		this->gbAlgorithmSign->Size = System::Drawing::Size(509, 155);
		this->gbAlgorithmSign->TabIndex = 23;
		this->gbAlgorithmSign->TabStop = false;
		this->gbAlgorithmSign->Text = L"Algorithm";
		// 
		// label1
		// 
		this->label1->AutoSize = true;
		this->label1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->label1->ForeColor = System::Drawing::SystemColors::ScrollBar;
		this->label1->Location = System::Drawing::Point(3, 51);
		this->label1->Name = L"label1";
		this->label1->Size = System::Drawing::Size(504, 13);
		this->label1->TabIndex = 26;
		this->label1->Text = L"_______________________________________________________________________";
		// 
		// pnEc
		// 
		this->pnEc->Controls->Add(this->rbEcDefault);
		this->pnEc->Controls->Add(this->lbElipticCurve);
		this->pnEc->Controls->Add(this->rbEcSecp);
		this->pnEc->Controls->Add(this->rbEcBrainPool);
		this->pnEc->Location = System::Drawing::Point(6, 119);
		this->pnEc->Name = L"pnEc";
		this->pnEc->Size = System::Drawing::Size(497, 29);
		this->pnEc->TabIndex = 25;
		this->pnEc->Paint += gcnew System::Windows::Forms::PaintEventHandler(this, &Crypto::pnEc_Paint);
		// 
		// rbEcDefault
		// 
		this->rbEcDefault->AutoSize = true;
		this->rbEcDefault->Checked = true;
		this->rbEcDefault->Location = System::Drawing::Point(133, 5);
		this->rbEcDefault->Name = L"rbEcDefault";
		this->rbEcDefault->Size = System::Drawing::Size(76, 21);
		this->rbEcDefault->TabIndex = 28;
		this->rbEcDefault->TabStop = true;
		this->rbEcDefault->Text = L"default";
		this->rbEcDefault->UseVisualStyleBackColor = true;
		// 
		// lbElipticCurve
		// 
		this->lbElipticCurve->AutoSize = true;
		this->lbElipticCurve->Location = System::Drawing::Point(15, 5);
		this->lbElipticCurve->Name = L"lbElipticCurve";
		this->lbElipticCurve->Size = System::Drawing::Size(102, 17);
		this->lbElipticCurve->TabIndex = 0;
		this->lbElipticCurve->Text = L"Eliptic curve:";
		// 
		// rbEcSecp
		// 
		this->rbEcSecp->AutoSize = true;
		this->rbEcSecp->Location = System::Drawing::Point(230, 5);
		this->rbEcSecp->Name = L"rbEcSecp";
		this->rbEcSecp->Size = System::Drawing::Size(104, 21);
		this->rbEcSecp->TabIndex = 26;
		this->rbEcSecp->Text = L"secp256k1";
		this->rbEcSecp->UseVisualStyleBackColor = true;
		// 
		// rbEcBrainPool
		// 
		this->rbEcBrainPool->AutoSize = true;
		this->rbEcBrainPool->Location = System::Drawing::Point(350, 7);
		this->rbEcBrainPool->Name = L"rbEcBrainPool";
		this->rbEcBrainPool->Size = System::Drawing::Size(136, 21);
		this->rbEcBrainPool->TabIndex = 27;
		this->rbEcBrainPool->Text = L"brainpool256r1";
		this->rbEcBrainPool->UseVisualStyleBackColor = true;
		// 
		// lbSignKeys
		// 
		this->lbSignKeys->AutoSize = true;
		this->lbSignKeys->ForeColor = System::Drawing::SystemColors::Highlight;
		this->lbSignKeys->Location = System::Drawing::Point(400, 17);
		this->lbSignKeys->Name = L"lbSignKeys";
		this->lbSignKeys->Size = System::Drawing::Size(82, 34);
		this->lbSignKeys->TabIndex = 23;
		this->lbSignKeys->Text = L"RSA keys\r\ngenerated";
		this->lbSignKeys->TextAlign = System::Drawing::ContentAlignment::TopCenter;
		this->lbSignKeys->Visible = false;
		// 
		// lbEcKey
		// 
		this->lbEcKey->AutoSize = true;
		this->lbEcKey->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->lbEcKey->Location = System::Drawing::Point(400, 74);
		this->lbEcKey->Name = L"lbEcKey";
		this->lbEcKey->Size = System::Drawing::Size(82, 34);
		this->lbEcKey->TabIndex = 24;
		this->lbEcKey->Text = L"EC keys\r\ngenerated";
		this->lbEcKey->TextAlign = System::Drawing::ContentAlignment::TopCenter;
		this->lbEcKey->Visible = false;
		// 
		// rbRsaSign
		// 
		this->rbRsaSign->AutoSize = true;
		this->rbRsaSign->Location = System::Drawing::Point(24, 32);
		this->rbRsaSign->Name = L"rbRsaSign";
		this->rbRsaSign->Size = System::Drawing::Size(57, 21);
		this->rbRsaSign->TabIndex = 0;
		this->rbRsaSign->Text = L"RSA";
		this->rbRsaSign->UseVisualStyleBackColor = true;
		this->rbRsaSign->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbRsaSign_CheckedChanged);
		// 
		// cbPublicKeyEc
		// 
		this->cbPublicKeyEc->AutoSize = true;
		this->cbPublicKeyEc->Enabled = false;
		this->cbPublicKeyEc->Location = System::Drawing::Point(270, 93);
		this->cbPublicKeyEc->Name = L"cbPublicKeyEc";
		this->cbPublicKeyEc->Size = System::Drawing::Size(101, 21);
		this->cbPublicKeyEc->TabIndex = 22;
		this->cbPublicKeyEc->Text = L"Public key";
		this->cbPublicKeyEc->UseVisualStyleBackColor = true;
		this->cbPublicKeyEc->CheckedChanged += gcnew System::EventHandler(this, &Crypto::cbPublicKeyEc_CheckedChanged);
		// 
		// cbPrivateKeyEc
		// 
		this->cbPrivateKeyEc->AutoSize = true;
		this->cbPrivateKeyEc->Enabled = false;
		this->cbPrivateKeyEc->Location = System::Drawing::Point(270, 73);
		this->cbPrivateKeyEc->Name = L"cbPrivateKeyEc";
		this->cbPrivateKeyEc->Size = System::Drawing::Size(108, 21);
		this->cbPrivateKeyEc->TabIndex = 22;
		this->cbPrivateKeyEc->Text = L"Private key";
		this->cbPrivateKeyEc->UseVisualStyleBackColor = true;
		this->cbPrivateKeyEc->CheckedChanged += gcnew System::EventHandler(this, &Crypto::cbPrivateKeyEc_CheckedChanged);
		// 
		// lbReafFromFileEc
		// 
		this->lbReafFromFileEc->AutoSize = true;
		this->lbReafFromFileEc->Location = System::Drawing::Point(112, 80);
		this->lbReafFromFileEc->Name = L"lbReafFromFileEc";
		this->lbReafFromFileEc->Size = System::Drawing::Size(120, 34);
		this->lbReafFromFileEc->TabIndex = 22;
		this->lbReafFromFileEc->Text = L"READ EC KEYS\r\nfrom file:";
		this->lbReafFromFileEc->TextAlign = System::Drawing::ContentAlignment::MiddleCenter;
		// 
		// rbEcSign
		// 
		this->rbEcSign->AutoSize = true;
		this->rbEcSign->Checked = true;
		this->rbEcSign->Location = System::Drawing::Point(25, 80);
		this->rbEcSign->Name = L"rbEcSign";
		this->rbEcSign->Size = System::Drawing::Size(46, 21);
		this->rbEcSign->TabIndex = 1;
		this->rbEcSign->TabStop = true;
		this->rbEcSign->Text = L"EC";
		this->rbEcSign->UseVisualStyleBackColor = true;
		this->rbEcSign->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbEcSign_CheckedChanged);
		// 
		// gbIO
		// 
		this->gbIO->Controls->Add(this->gbOutput);
		this->gbIO->Controls->Add(this->gbInput);
		this->gbIO->Controls->Add(this->gbSymmetricKey);
		this->gbIO->Controls->Add(this->tbPublicKey);
		this->gbIO->Controls->Add(this->gbPrivateKey);
		this->gbIO->Location = System::Drawing::Point(741, 46);
		this->gbIO->Name = L"gbIO";
		this->gbIO->Size = System::Drawing::Size(685, 760);
		this->gbIO->TabIndex = 17;
		this->gbIO->TabStop = false;
		this->gbIO->Text = L"IO";
		this->gbIO->Enter += gcnew System::EventHandler(this, &Crypto::gbIO_Enter);
		// 
		// gbOutput
		// 
		this->gbOutput->Controls->Add(this->lbOutAlg);
		this->gbOutput->Controls->Add(this->cbUnlockOutput);
		this->gbOutput->Controls->Add(this->btClearInput);
		this->gbOutput->Controls->Add(this->rtbOutput);
		this->gbOutput->Controls->Add(this->btClear);
		this->gbOutput->Controls->Add(this->lbOutput);
		this->gbOutput->Location = System::Drawing::Point(20, 536);
		this->gbOutput->Name = L"gbOutput";
		this->gbOutput->Size = System::Drawing::Size(643, 201);
		this->gbOutput->TabIndex = 19;
		this->gbOutput->TabStop = false;
		this->gbOutput->Text = L"Output";
		// 
		// lbOutAlg
		// 
		this->lbOutAlg->AutoSize = true;
		this->lbOutAlg->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->lbOutAlg->Location = System::Drawing::Point(254, 177);
		this->lbOutAlg->Name = L"lbOutAlg";
		this->lbOutAlg->Size = System::Drawing::Size(0, 17);
		this->lbOutAlg->TabIndex = 14;
		this->lbOutAlg->Visible = false;
		// 
		// cbUnlockOutput
		// 
		this->cbUnlockOutput->AutoSize = true;
		this->cbUnlockOutput->Location = System::Drawing::Point(420, 176);
		this->cbUnlockOutput->Name = L"cbUnlockOutput";
		this->cbUnlockOutput->Size = System::Drawing::Size(74, 21);
		this->cbUnlockOutput->TabIndex = 11;
		this->cbUnlockOutput->Text = L"unlock";
		this->cbUnlockOutput->UseVisualStyleBackColor = true;
		this->cbUnlockOutput->CheckedChanged += gcnew System::EventHandler(this, &Crypto::cbUnlockOutput_CheckedChanged);
		// 
		// gbInput
		// 
		this->gbInput->Controls->Add(this->lbInputError);
		this->gbInput->Controls->Add(this->rtbInput);
		this->gbInput->Location = System::Drawing::Point(21, 32);
		this->gbInput->Name = L"gbInput";
		this->gbInput->Size = System::Drawing::Size(642, 129);
		this->gbInput->TabIndex = 19;
		this->gbInput->TabStop = false;
		this->gbInput->Text = L"Input";
		// 
		// lbInputError
		// 
		this->lbInputError->AutoSize = true;
		this->lbInputError->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 10, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->lbInputError->ForeColor = System::Drawing::Color::Red;
		this->lbInputError->Location = System::Drawing::Point(151, 109);
		this->lbInputError->Name = L"lbInputError";
		this->lbInputError->Size = System::Drawing::Size(174, 17);
		this->lbInputError->TabIndex = 16;
		this->lbInputError->Text = L"Input error - enter text!";
		this->lbInputError->Visible = false;
		// 
		// gbSymmetricKey
		// 
		this->gbSymmetricKey->Controls->Add(this->rtbKey);
		this->gbSymmetricKey->Controls->Add(this->lbKeyLentgh);
		this->gbSymmetricKey->Controls->Add(this->lbKey);
		this->gbSymmetricKey->Controls->Add(this->btEnterKey);
		this->gbSymmetricKey->Controls->Add(this->lbKeyError);
		this->gbSymmetricKey->Controls->Add(this->cbHexKey);
		this->gbSymmetricKey->Location = System::Drawing::Point(21, 175);
		this->gbSymmetricKey->Name = L"gbSymmetricKey";
		this->gbSymmetricKey->Size = System::Drawing::Size(642, 112);
		this->gbSymmetricKey->TabIndex = 18;
		this->gbSymmetricKey->TabStop = false;
		this->gbSymmetricKey->Text = L"Symmetric Key";
		// 
		// tbPublicKey
		// 
		this->tbPublicKey->Controls->Add(this->lbPublicKey);
		this->tbPublicKey->Controls->Add(this->checkBox1);
		this->tbPublicKey->Controls->Add(this->rtbPublicKey);
		this->tbPublicKey->Location = System::Drawing::Point(21, 417);
		this->tbPublicKey->Name = L"tbPublicKey";
		this->tbPublicKey->Size = System::Drawing::Size(642, 108);
		this->tbPublicKey->TabIndex = 16;
		this->tbPublicKey->TabStop = false;
		this->tbPublicKey->Text = L"Public Key";
		// 
		// lbPublicKey
		// 
		this->lbPublicKey->AutoSize = true;
		this->lbPublicKey->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->lbPublicKey->Location = System::Drawing::Point(22, 86);
		this->lbPublicKey->Name = L"lbPublicKey";
		this->lbPublicKey->Size = System::Drawing::Size(0, 17);
		this->lbPublicKey->TabIndex = 21;
		// 
		// checkBox1
		// 
		this->checkBox1->AutoSize = true;
		this->checkBox1->Location = System::Drawing::Point(552, 85);
		this->checkBox1->Name = L"checkBox1";
		this->checkBox1->Size = System::Drawing::Size(74, 21);
		this->checkBox1->TabIndex = 12;
		this->checkBox1->Text = L"unlock";
		this->checkBox1->UseVisualStyleBackColor = true;
		this->checkBox1->CheckedChanged += gcnew System::EventHandler(this, &Crypto::checkBox1_CheckedChanged);
		// 
		// rtbPublicKey
		// 
		this->rtbPublicKey->Enabled = false;
		this->rtbPublicKey->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->rtbPublicKey->Location = System::Drawing::Point(15, 22);
		this->rtbPublicKey->Name = L"rtbPublicKey";
		this->rtbPublicKey->Size = System::Drawing::Size(612, 63);
		this->rtbPublicKey->TabIndex = 18;
		this->rtbPublicKey->Text = L"";
		// 
		// gbPrivateKey
		// 
		this->gbPrivateKey->AutoSizeMode = System::Windows::Forms::AutoSizeMode::GrowAndShrink;
		this->gbPrivateKey->Controls->Add(this->lbPrivateKey);
		this->gbPrivateKey->Controls->Add(this->checkBox2);
		this->gbPrivateKey->Controls->Add(this->rtbPrivateKey);
		this->gbPrivateKey->Location = System::Drawing::Point(21, 303);
		this->gbPrivateKey->Name = L"gbPrivateKey";
		this->gbPrivateKey->Size = System::Drawing::Size(642, 108);
		this->gbPrivateKey->TabIndex = 17;
		this->gbPrivateKey->TabStop = false;
		this->gbPrivateKey->Text = L"Private Key";
		// 
		// lbPrivateKey
		// 
		this->lbPrivateKey->AutoSize = true;
		this->lbPrivateKey->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->lbPrivateKey->Location = System::Drawing::Point(25, 85);
		this->lbPrivateKey->Name = L"lbPrivateKey";
		this->lbPrivateKey->Size = System::Drawing::Size(0, 17);
		this->lbPrivateKey->TabIndex = 20;
		// 
		// checkBox2
		// 
		this->checkBox2->AutoSize = true;
		this->checkBox2->Location = System::Drawing::Point(553, 85);
		this->checkBox2->Name = L"checkBox2";
		this->checkBox2->Size = System::Drawing::Size(74, 21);
		this->checkBox2->TabIndex = 19;
		this->checkBox2->Text = L"unlock";
		this->checkBox2->UseVisualStyleBackColor = true;
		this->checkBox2->CheckedChanged += gcnew System::EventHandler(this, &Crypto::checkBox2_CheckedChanged);
		// 
		// rtbPrivateKey
		// 
		this->rtbPrivateKey->Enabled = false;
		this->rtbPrivateKey->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
			static_cast<System::Byte>(0)));
		this->rtbPrivateKey->Location = System::Drawing::Point(15, 22);
		this->rtbPrivateKey->MaximumSize = System::Drawing::Size(685, 737);
		this->rtbPrivateKey->Name = L"rtbPrivateKey";
		this->rtbPrivateKey->Size = System::Drawing::Size(612, 63);
		this->rtbPrivateKey->TabIndex = 19;
		this->rtbPrivateKey->Text = L"";
		// 
		// gbAsymmetric
		// 
		this->gbAsymmetric->Controls->Add(this->btGenerateRsa);
		this->gbAsymmetric->Controls->Add(this->gbAsymAlgorithm);
		this->gbAsymmetric->Location = System::Drawing::Point(17, 33);
		this->gbAsymmetric->Name = L"gbAsymmetric";
		this->gbAsymmetric->Size = System::Drawing::Size(681, 104);
		this->gbAsymmetric->TabIndex = 16;
		this->gbAsymmetric->TabStop = false;
		this->gbAsymmetric->Text = L"Asymmetric encryption";
		// 
		// btGenerateRsa
		// 
		this->btGenerateRsa->Location = System::Drawing::Point(548, 30);
		this->btGenerateRsa->Name = L"btGenerateRsa";
		this->btGenerateRsa->Size = System::Drawing::Size(116, 62);
		this->btGenerateRsa->TabIndex = 17;
		this->btGenerateRsa->Text = L"GENERATE RSA KEYS";
		this->btGenerateRsa->UseVisualStyleBackColor = true;
		this->btGenerateRsa->Click += gcnew System::EventHandler(this, &Crypto::btGenerateRsa_Click);
		// 
		// gbAsymAlgorithm
		// 
		this->gbAsymAlgorithm->Controls->Add(this->lbRsaGenerated);
		this->gbAsymAlgorithm->Controls->Add(this->lbReadFromFile);
		this->gbAsymAlgorithm->Controls->Add(this->cbShowPublicKey);
		this->gbAsymAlgorithm->Controls->Add(this->cbShowPrivateKey);
		this->gbAsymAlgorithm->Controls->Add(this->rbRsa);
		this->gbAsymAlgorithm->Location = System::Drawing::Point(18, 22);
		this->gbAsymAlgorithm->Name = L"gbAsymAlgorithm";
		this->gbAsymAlgorithm->Size = System::Drawing::Size(506, 70);
		this->gbAsymAlgorithm->TabIndex = 22;
		this->gbAsymAlgorithm->TabStop = false;
		this->gbAsymAlgorithm->Text = L"Algorithm";
		// 
		// lbRsaGenerated
		// 
		this->lbRsaGenerated->AutoSize = true;
		this->lbRsaGenerated->ForeColor = System::Drawing::SystemColors::HotTrack;
		this->lbRsaGenerated->Location = System::Drawing::Point(397, 26);
		this->lbRsaGenerated->Name = L"lbRsaGenerated";
		this->lbRsaGenerated->Size = System::Drawing::Size(82, 34);
		this->lbRsaGenerated->TabIndex = 22;
		this->lbRsaGenerated->Text = L"RSA keys\r\ngenerated";
		this->lbRsaGenerated->TextAlign = System::Drawing::ContentAlignment::TopCenter;
		this->lbRsaGenerated->Visible = false;
		// 
		// lbReadFromFile
		// 
		this->lbReadFromFile->AutoSize = true;
		this->lbReadFromFile->Location = System::Drawing::Point(109, 26);
		this->lbReadFromFile->Name = L"lbReadFromFile";
		this->lbReadFromFile->Size = System::Drawing::Size(131, 34);
		this->lbReadFromFile->TabIndex = 21;
		this->lbReadFromFile->Text = L"READ RSA KEYS\r\nfrom file:";
		this->lbReadFromFile->TextAlign = System::Drawing::ContentAlignment::MiddleCenter;
		// 
		// cbShowPublicKey
		// 
		this->cbShowPublicKey->AutoSize = true;
		this->cbShowPublicKey->Enabled = false;
		this->cbShowPublicKey->Location = System::Drawing::Point(267, 40);
		this->cbShowPublicKey->Name = L"cbShowPublicKey";
		this->cbShowPublicKey->Size = System::Drawing::Size(101, 21);
		this->cbShowPublicKey->TabIndex = 20;
		this->cbShowPublicKey->Text = L"Public key";
		this->cbShowPublicKey->UseVisualStyleBackColor = true;
		this->cbShowPublicKey->CheckedChanged += gcnew System::EventHandler(this, &Crypto::cbShowPublicKey_CheckedChanged);
		// 
		// cbShowPrivateKey
		// 
		this->cbShowPrivateKey->AutoSize = true;
		this->cbShowPrivateKey->Enabled = false;
		this->cbShowPrivateKey->Location = System::Drawing::Point(267, 21);
		this->cbShowPrivateKey->Name = L"cbShowPrivateKey";
		this->cbShowPrivateKey->Size = System::Drawing::Size(108, 21);
		this->cbShowPrivateKey->TabIndex = 19;
		this->cbShowPrivateKey->Text = L"Private key";
		this->cbShowPrivateKey->UseVisualStyleBackColor = true;
		this->cbShowPrivateKey->CheckedChanged += gcnew System::EventHandler(this, &Crypto::cbShowPrivateKey_CheckedChanged);
		// 
		// rbRsa
		// 
		this->rbRsa->AutoSize = true;
		this->rbRsa->Checked = true;
		this->rbRsa->Location = System::Drawing::Point(22, 33);
		this->rbRsa->Name = L"rbRsa";
		this->rbRsa->Size = System::Drawing::Size(57, 21);
		this->rbRsa->TabIndex = 17;
		this->rbRsa->TabStop = true;
		this->rbRsa->Text = L"RSA";
		this->rbRsa->UseVisualStyleBackColor = true;
		this->rbRsa->CheckedChanged += gcnew System::EventHandler(this, &Crypto::rbRsa_CheckedChanged);
		// 
		// Crypto
		// 
		this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
		this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
		this->ClientSize = System::Drawing::Size(1510, 854);
		this->Controls->Add(this->rtbReadPrivPubKey);
		this->Controls->Add(this->gbCrypto);
		this->Name = L"Crypto";
		this->Text = L"Crypto";
		this->gbSymmetric->ResumeLayout(false);
		this->gbSymMode->ResumeLayout(false);
		this->gbSymMode->PerformLayout();
		this->gbSymAlgorithm->ResumeLayout(false);
		this->gbSymAlgorithm->PerformLayout();
		this->gbHashMac->ResumeLayout(false);
		this->gbMacMode->ResumeLayout(false);
		this->gbMacMode->PerformLayout();
		this->gbMacAlgorithm->ResumeLayout(false);
		this->gbMacAlgorithm->PerformLayout();
		this->gbCrypto->ResumeLayout(false);
		this->gbCertificate->ResumeLayout(false);
		this->gbCertAlg->ResumeLayout(false);
		this->gbCertAlg->PerformLayout();
		this->gbSign->ResumeLayout(false);
		this->gbAlgorithmSign->ResumeLayout(false);
		this->gbAlgorithmSign->PerformLayout();
		this->pnEc->ResumeLayout(false);
		this->pnEc->PerformLayout();
		this->gbIO->ResumeLayout(false);
		this->gbOutput->ResumeLayout(false);
		this->gbOutput->PerformLayout();
		this->gbInput->ResumeLayout(false);
		this->gbInput->PerformLayout();
		this->gbSymmetricKey->ResumeLayout(false);
		this->gbSymmetricKey->PerformLayout();
		this->tbPublicKey->ResumeLayout(false);
		this->tbPublicKey->PerformLayout();
		this->gbPrivateKey->ResumeLayout(false);
		this->gbPrivateKey->PerformLayout();
		this->gbAsymmetric->ResumeLayout(false);
		this->gbAsymAlgorithm->ResumeLayout(false);
		this->gbAsymAlgorithm->PerformLayout();
		this->ResumeLayout(false);

	}

		//################# CONVERT STRINGS #######################

	private:std::string ConvertToCppString(String^ str) {

		return msclr::interop::marshal_as<std::string>(str);
	}

	private:std::string ConvertToCppString(unsigned char* str) {

		std::stringstream s;
		s << str;

		return s.str();
	}

	private:std::string ConvertToCppString(int num) {

		return std::to_string(num);
	}

	private:unsigned char* ConvertToChar(std::string str) {

		unsigned int i = 0;
		unsigned char* data = (unsigned char*)malloc(BUFFER);
		for (i = 0; i < str.size(); ++i) {
			
			data[i] = static_cast<unsigned char>(str[i]);
		}
		data[i] = '\0';
			
		return data;
	}

	private:String^ ConvertToCharpString(std::string& str) {

		return msclr::interop::marshal_as<String^>(str);
	}

	private:void ConvertStringToHex(void* const data, size_t len, std::string& dest)
	{
		unsigned char* byteData = reinterpret_cast<unsigned char*>(data);
		std::stringstream hexStream;

		hexStream << std::hex << std::setfill('0');

		for (size_t i = 0; i < len; ++i)
			hexStream << std::setw(2) << static_cast<int>(byteData[i]);

		dest = hexStream.str();
	}

	private:void ConvertStringFromHex(const std::string& input, void* data)
	{
		size_t len = input.length();
		unsigned char* byteData = reinterpret_cast<unsigned char*>(data);

		std::stringstream hexStream;
		hexStream >> std::hex;

		for (size_t i = 0, j = 0; i < len; ++j)
		{
			const char tmpStr[3] = { input[i++], input[i++], 0 };

			hexStream.clear();
			hexStream.str(tmpStr);

			int tmp = 0;
			hexStream >> tmp;
			byteData[j] = static_cast<unsigned char>(tmp);
		}
	}

		//################# CONVERT STRINGS #######################
		
	private:char* getCurveNid() {
		
		if (rbEcSecp->Checked) return "secp256k1";
		else if (rbEcBrainPool->Checked) return "brainpool256r1";
		else return "default";
	}
		
	private:char* getMacType() {

		if (rbHmac->Checked) return "HMAC";
		else if (rbCmac->Checked) return "CMAC";
	}

	private:char* getHashType() {

		if (rbMd5->Checked) return "MD5";
		else if (rbSha1->Checked) return "SHA1";
		else if (rbSha256->Checked) return "SHA256";
		else if (rbSha384->Checked) return "SHA384";
		else if (rbSha512->Checked) return "SHA512";
	}

	private:char* getEncryptType() {

		if (rbDes->Checked) { sm.setKeyLen(8); return "DES"; }
		else if (rbTdes->Checked) { sm.setKeyLen(16); return "TDES"; }
		else if (rbAes128->Checked) { sm.setKeyLen(16); return "AES128"; }
		else if (rbAes256->Checked) { sm.setKeyLen(32); return "AES256"; }
		else if (rbRc4->Checked) { sm.setKeyLen(16); return "RC4"; }
	}

	private:char* getEncryptMode() {
		
		if (rbEcb->Checked) return "ECB";
		else if (rbCbc->Checked) return "CBC";
	}

	private:void encryptText(Symmetric& sm) {

		try
		{
			sm.setType(getEncryptType());
			sm.setMode(getEncryptMode());

			sm.setPadding(cbPadding->Checked ? 1 : 0);

			std::string str = ConvertToCppString(rtbInput->Text->Trim());
			unsigned char* plaintext = (unsigned char*)malloc(BUFFER);
			if (plaintext == NULL) throw std::runtime_error(__func__);
			plaintext = ConvertToChar(str);

			sm.setInText(plaintext);
			int plain_len = strlen((char*)plaintext);
			sm.setInLen(plain_len);

			if (plain_len)
				sm.encrypt();
			
			unsigned char ciphertext[BUFFER], key[BUFFER];
			int ciphertext_len = sm.getOutLen();
			memcpy(ciphertext, sm.getOutText(), ciphertext_len);
			ciphertext[ciphertext_len] = '\0';

			std::string to_hex;
			ConvertStringToHex(ciphertext, ciphertext_len, to_hex);
			rtbOutput->Text = ConvertToCharpString(to_hex);

			int key_len = sm.getKeyLen();
			memcpy(key, sm.getKey(), key_len);
			std::string key_hex;
			ConvertStringToHex(key, key_len, key_hex);
			if(!sm.getEnterKey())
				rtbKey->Text = ConvertToCharpString(key_hex);

			free(plaintext);
		}
		catch (Exception^ e)
		{
			MessageBox::Show("Symmetric encryption failed!\n" + e->Message);
		}
	}

	private:void decryptText(Symmetric& sm) {

		try
		{
			std::string str_cipher = ConvertToCppString(rtbOutput->Text->Trim());
			unsigned char from_hex[BUFFER];
			ConvertStringFromHex(str_cipher, from_hex);
			sm.setInText(from_hex);
			sm.setInLen(strlen((char*)from_hex));

			sm.decrypt();

			unsigned char plaintext[BUFFER];
			int plaintext_len = sm.getOutLen();
			memcpy(plaintext, sm.getOutText(), plaintext_len);
			plaintext[plaintext_len] = '\0';

			rtbOutput->Text = ConvertToCharpString(ConvertToCppString(plaintext));
		}
		catch (Exception^ e)
		{
			MessageBox::Show("Symmetric decryption failed!\n" + e->Message);
		}
	}

	private:void disableControl(int ind_all, int ind_key) {
		
		bool enable = true;

		if (ind_all) {
			enable = false;
			if (ind_key)
				btEncrypt->Text = "DECRYPT";
		}
		else
			btEncrypt->Text = "ENCRYPT";

		rtbInput->Enabled = enable;
		rbDes->Enabled = enable;
		rbTdes->Enabled = enable;
		rbAes128->Enabled = enable;
		rbAes256->Enabled = enable;
		rbRc4->Enabled = enable;

		cbPadding->Enabled = enable;
		rbCbc->Enabled = enable;
		rbEcb->Enabled = enable;

		gbHashMac->Enabled = enable;
		gbAsymmetric->Enabled = enable;
		gbSign->Enabled = enable;
		gbPrivateKey->Enabled = enable;
		gbCertificate->Enabled = enable;
		tbPublicKey->Enabled = enable;

		btHash->Enabled = enable;
		btMac->Enabled = enable;
		btClearInput->Enabled = enable;
		if (ind_key)
			btEnterKey->Enabled = enable;
	}

	private: System::Void btEncrypt_Click(System::Object^ sender, System::EventArgs^ e) {

		std::string str = ConvertToCppString(rtbInput->Text->Trim());
		if (!str.size()) {
			lbInputError->Visible = true;
			return;
		}
		else
			lbInputError->Visible = false;

		if (!ind_ob) {

			lbOutput->Text = "";
			lbOutAlg->Visible = true;
			rtbOutput->Enabled = false;
			cbUnlockOutput->Checked = false;
			lbOutput->ForeColor = SystemColors::HotTrack;

			try
			{
				encryptText(sm);
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Symmetric encryption failed!\n" + e->Message);
			}

			disableControl(1, 1);

			lbOutput->Text = "Encrypted text";
			lbOutAlg->Visible = true;
			lbOutAlg->Text = ConvertToCharpString(ConvertToCppString((unsigned char*)getEncryptType()));
			ind_ob = 1;
		}
		else if (ind_ob) {
		
			lbOutput->Text = "";
			lbOutAlg->Visible = true;
			rtbOutput->Enabled = false;
			cbUnlockOutput->Checked = false;
			lbOutput->ForeColor = SystemColors::HotTrack;

			try
			{
				decryptText(sm);
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Symmetric decryption failed!\n" + e->Message);
			}

			disableControl(0, 1);

			lbOutput->Text = "Decrypted text";
			lbOutAlg->Visible = true;
			lbOutAlg->Text = ConvertToCharpString(ConvertToCppString((unsigned char*)getEncryptType()));
			ind_ob = 0;
		}
	}

	private: System::Void btClear_Click(System::Object^ sender, System::EventArgs^ e) {

		btGenRootCert->Enabled = true;
		btEncrypt->Enabled = true;
		btEncrypt->Text = "ENCRYPT";
		btEnterKey->Text = "ENTER KEY";
		btGenRootCert->Text = "GENERATED\nROOT CA";

		lbKeyError->ResetText();
		lbOutput->ResetText();
		lbPrivateKey->ResetText();
		lbPublicKey->ResetText();
		lbOutAlg->ResetText();
		lbInputError->Visible = false;
		lbOutAlg->Visible = false;
		lbCAgen->Visible = false;
		lbCertReq->Visible = false;
		lbCertFromReq->Visible = false;

		cbHexKey->Checked = true;
		cbShowPrivateKey->Checked = false;
		cbShowPublicKey->Checked = false;
		cbRootCA->Checked = false;
		cbReadCert->Checked = false;
		cbReadCertReq->Checked = false;

		rtbInput->Clear();
		rtbOutput->Clear();
		rtbKey->Clear();
		rtbKey->Enabled = false;

		rbMd5->Select();
		rbDes->Select();
		rbCbc->Select();
		rbHmac->Select();
		rbRsa->Select();

		gbSymmetric->Enabled = true;
		gbHashMac->Enabled = true;
		gbSign->Enabled = true;
		gbSymmetricKey->Enabled = true;

		sm.setEnterKey(0);
		sm.restartKey();

		ind_ob = 0;
		ind_key = 0;
		ind_ca = 0;
		ind_cert = 0;
		ind_req = 0;

		if (as.getInLen()) {

			btGenerateRsa->Text = "ENCRYPT";
			ind_rsa = 1;
			ind_once = 1;
		}

		disableControl(0, 1);
	}

	private:bool validateKey(int len) {
	
		if (rbDes->Checked && len == 8) return true;
		else if (rbTdes->Checked && len == 16) return true;
		else if (rbAes128->Checked && len == 16) return true;
		else if (rbAes256->Checked && len == 32) return true;
		else if (rbRc4->Checked && len == 16) return true;

		return false;
	}

	private:void generateEnterKey() {

		try
		{
			std::string str_key = ConvertToCppString(rtbKey->Text->Trim());
			unsigned char* key = (unsigned char*)malloc(BUFFER);
			if (key == NULL) throw std::runtime_error(__func__);
			key = ConvertToChar(str_key);
		
			int key_len = strlen((char*)key);
			if (validateKey(key_len)) {
			
				lbKeyError->ResetText();
			
				sm.setEnterKey(1);
				sm.setKeyLen(key_len);
				sm.setKey(key);
			}
			else {
				lbKeyError->Text = "Invalid key length!";
				sm.restartKey();
				sm.setEnterKey(0);
				btEncrypt->Enabled = false;

				disableControl(1, 0);
			}

			free(key);
		}
		catch (Exception^ e)
		{
			MessageBox::Show("Generate symmetric user key failed!\n" + e->Message);
		}
	}

	private: System::Void btEnterKey_Click(System::Object^ sender, System::EventArgs^ e) {

		if (!ind_key) {

			disableControl(1, 0);
		
			btEnterKey->Text = "CONFIRM";
			btEncrypt->Enabled = false;
			rtbKey->Enabled = true;
			cbHexKey->Checked = false;
			rtbKey->Clear();

			ind_key = 1;
		}
		else if (ind_key) {

			disableControl(0, 0);

			generateEnterKey();
			
			btEnterKey->Text = "ENTER KEY";
			btEncrypt->Enabled = true;
			rtbKey->Enabled = false;
			cbHexKey->Checked = true;

			ind_key = 0;
		}
	}
	
	private: System::Void btClearInput_Click(System::Object^ sender, System::EventArgs^ e) {

		lbOutput->Text = "Output";
		lbOutput->ForeColor = SystemColors::HotTrack;
		rtbInput->Clear();
		rtbOutput->Clear();
		lbOutAlg->ResetText();
		lbOutAlg->Visible = false;
		rtbOutput->Enabled = false;
		cbUnlockOutput->Checked = false;
	}
	
	private: System::Void cbHexKey_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {

		if (cbHexKey->Checked) {

			std::string key_hex;
			ConvertStringToHex(sm.getKey(), sm.getKeyLen(), key_hex);
			rtbKey->Text = ConvertToCharpString(key_hex);
		}
		else if(lbKeyError->Text)
			rtbKey->Text = ConvertToCharpString(ConvertToCppString(sm.getKey()));
	}

	private: System::Void btHash_Click(System::Object^ sender, System::EventArgs^ e) {
	
		std::string str = ConvertToCppString(rtbInput->Text->Trim());
		if (!str.size()) {
			lbInputError->Visible = true;
			return;
		}
		else
			lbInputError->Visible = false;

		lbOutput->Text = "";
		lbOutAlg->Visible = true;
		rtbOutput->Enabled = false;
		cbUnlockOutput->Checked = false;
		lbOutput->ForeColor = SystemColors::HotTrack;

		try
		{
			Hash hs;

			hs.Hash::setType(getHashType());
			rtbKey->Clear();

			unsigned char* plaintext = (unsigned char*)malloc(BUFFER);
			if (plaintext == NULL) throw std::runtime_error(__func__);
			plaintext = ConvertToChar(str);

			hs.setInText(plaintext);
			unsigned int plain_len = strlen((char*)plaintext);
			hs.setInLen(plain_len);

			hs.hashText();

			unsigned char hashtext[EVP_MAX_MD_SIZE];
			unsigned int hashtext_len = hs.getOutLen();
			memcpy(hashtext, hs.getOutText(), hashtext_len);
			hashtext[hashtext_len] = '\0';

			std::string to_hex;
			ConvertStringToHex(hashtext, hashtext_len, to_hex);
			rtbOutput->Text = ConvertToCharpString(to_hex);

			lbOutput->Text = "Hash code";
			lbOutAlg->Visible = true;
			lbOutAlg->Text = ConvertToCharpString(ConvertToCppString((unsigned char*)getHashType()));

			free(plaintext);
		}
		catch (Exception^ e)
		{
			MessageBox::Show("Hash text failed!\n" + e->Message);
		}
	}
	
	private: System::Void btMac_Click(System::Object^ sender, System::EventArgs^ e) {
	
		std::string str = ConvertToCppString(rtbInput->Text->Trim());
		if (!str.size()) {
			lbInputError->Visible = true;
			return;
		}
		else
			lbInputError->Visible = false;

		lbOutput->Text = "";
		lbOutAlg->Visible = true;
		rtbOutput->Enabled = false;
		cbUnlockOutput->Checked = false;
		lbOutput->ForeColor = SystemColors::HotTrack;

		try
		{
			Mac mc;

			mc.setMacType(getMacType());
			mc.setHashType(getHashType());
			rtbKey->Clear();

			unsigned char* plaintext = (unsigned char*)malloc(BUFFER);
			if (plaintext == NULL) throw std::runtime_error(__func__);
			plaintext = ConvertToChar(str);

			mc.setInText(plaintext);
			unsigned int plain_len = strlen((char*)plaintext);
			mc.setInLen(plain_len);

			mc.generateMac();
		
			unsigned char signtext[EVP_MAX_MD_SIZE];
			unsigned int mactext_len = mc.getOutLen();
			memcpy(signtext, mc.getOutText(), mactext_len);
			signtext[mactext_len] = '\0';

			std::string to_hex;
			ConvertStringToHex(signtext, mactext_len, to_hex);
			rtbOutput->Text = ConvertToCharpString(to_hex);

			lbOutput->Text = "Mac code";
			lbOutAlg->Visible = true;
			lbOutAlg->Text = ConvertToCharpString(ConvertToCppString((unsigned char*)getMacType()));

			free(plaintext);

		}
		catch (Exception^ e)
		{
			MessageBox::Show("MAC text failed!\n" + e->Message);
		}
	}
	
	private:void generateRsaKeyPair() {
		 
		try
		{		
			char* public_key_path_pem = "..\\PublicKey_RSA\\rsa_public_key.pem";
			as.setPublicKeyPathPem(public_key_path_pem);
			char* public_key_path_der = "..\\PublicKey_RSA\\rsa_public_key.der";
			as.setPublicKeyPathDer(public_key_path_der);
			
			char* private_key_path_pem = "..\\PrivateKey_RSA\\rsa_private_key.pem";
			as.setPrivateKeyPathPem(private_key_path_pem);
			char* private_key_path_der = "..\\PrivateKey_RSA\\rsa_private_key.der";
			as.setPrivateKeyPathDer(private_key_path_der);
			
			as.generateRsaKeyPair();

			std::string to_hex_private;
			ConvertStringToHex(as.getRsaPrivateKey(), as.getPrivateKeyLen(), to_hex_private);
			rtbPrivateKey->Text = ConvertToCharpString(to_hex_private);
			
			std::string to_hex_public;
			ConvertStringToHex(as.getRsaPublicKey(), as.getPublicKeyLen(), to_hex_public);
			rtbPublicKey->Text = ConvertToCharpString(to_hex_public);

			lbPrivateKey->Text = "RSA key";
			lbPublicKey->Text = "RSA key";
		}
		catch (Exception^ e)
		{
			MessageBox::Show("Generated RSA key pair failed!\n" + e->Message);
		}
	}
	
	private:void encryptRsa() {
			
		try
		{
			std::string str = ConvertToCppString(rtbInput->Text->Trim());
			unsigned char* plaintext = (unsigned char*)malloc(BUFFER);
			if (plaintext == NULL) throw std::runtime_error(__func__);
			plaintext = ConvertToChar(str);

			as.setInText(plaintext);
			unsigned int plain_len = strlen((char*)plaintext);
			as.setInLen(plain_len);

			as.encryptRsa();
			
			unsigned char rsatext[BUFFER];
			unsigned int rsatext_len = as.getOutLen();
			memcpy(rsatext, as.getOutText(), rsatext_len);
			rsatext[rsatext_len] = '\0';

			std::string to_hex;
			ConvertStringToHex(rsatext, rsatext_len, to_hex);
			rtbOutput->Text = ConvertToCharpString(to_hex);

			free(plaintext);
		}
		catch (Exception^ e)
		{
			MessageBox::Show("RSA encryption failed!\n" + e->Message);
		}

	}

	private:void decryptRsa() {
	
		try
		{
			std::string str_cipher = ConvertToCppString(rtbOutput->Text->Trim());
			unsigned char from_hex[BUFFER];
			ConvertStringFromHex(str_cipher, from_hex);
			as.setInText(from_hex);

			as.decryptRsa();

			unsigned char plaintext[BUFFER];
			int plaintext_len = as.getOutLen();
			memcpy(plaintext, as.getOutText(), plaintext_len);
			plaintext[plaintext_len] = '\0';

			rtbOutput->Text = ConvertToCharpString(ConvertToCppString(plaintext));
		}
		catch (Exception^ e)
		{
			MessageBox::Show("RSA decryption failed!\n" + e->Message);
		}
	}

	private: System::Void btGenerateRsa_Click(System::Object^ sender, System::EventArgs^ e) {

		if (!ind_rsa && !ind_once) {
		
			cbShowPrivateKey->Enabled = true;
			cbShowPublicKey->Enabled = true;
			lbRsaGenerated->Visible = true;
			lbSignKeys->Text = "RSA keys\ngenerated";
			lbSignKeys->Visible = true;
			btSignVerify->Enabled = true;
			lbSignKeys->ForeColor = SystemColors::HotTrack;
			lbOutput->ForeColor = SystemColors::HotTrack;

			try
			{
				generateRsaKeyPair();
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Generated RSA key pair failed!\n" + e->Message);
			}

			btGenerateRsa->Text = "ENCRYPT";
			ind_rsa = 1;
			ind_once = 1;
		}
		else if (ind_rsa == 1) {

			rtbOutput->Enabled = false;
			cbUnlockOutput->Checked = false;
			lbOutput->ForeColor = SystemColors::HotTrack;

			try
			{
				std::string str = ConvertToCppString(rtbInput->Text->Trim());
				if (!str.size()) {
					lbInputError->Visible = true;
					return;
				}
				else
					lbInputError->Visible = false;

				encryptRsa();
			}
			catch (Exception^ e)
			{
				MessageBox::Show("RSA encryption failed!\n" + e->Message);
			}
		
			btGenerateRsa->Text = "DECRYPT";
			lbOutput->Text = "Encrypted text";
			lbOutAlg->Visible = true;
			gbSymmetric->Enabled = false;
			gbHashMac->Enabled = false;
			gbSign->Enabled = false;
			gbSymmetricKey->Enabled = false;
			gbCertificate->Enabled = false;
			lbOutAlg->Text = ConvertToCharpString(ConvertToCppString("RSA"));

			ind_rsa = 2;
		}
		else if (ind_rsa == 2) {

			rtbOutput->Enabled = false;
			cbUnlockOutput->Checked = false;
			lbOutput->ForeColor = SystemColors::HotTrack;

			try
			{
				decryptRsa();
			}
			catch (Exception^ e)
			{
				MessageBox::Show("RSA decription failed!\n" + e->Message);
			}
		
			btGenerateRsa->Text = "ENCRYPT";
			lbOutput->Text = "Decrypted text";
			lbOutAlg->Visible = true;
			gbSymmetric->Enabled = true;
			gbHashMac->Enabled = true;
			gbSign->Enabled = true;
			gbSymmetricKey->Enabled = true;
			gbCertificate->Enabled = true;
			lbOutAlg->Text = ConvertToCharpString(ConvertToCppString("RSA"));

			ind_rsa = 1;
		}
	}
	
	private: System::Void cbShowPrivateKey_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {

		if (cbShowPrivateKey->Checked) {

			cbShowPublicKey->Checked = false;
			cbPrivateKeyEc->Checked = false;
			cbPublicKeyEc->Checked = false;

			unsigned char private_key[BUFFER];

			try
			{
				as.readPrivateKeyFromFile(private_key);
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Read RSA private key failed!\n" + e->Message);
			}

			rtbReadPrivPubKey->Visible = true;
			rtbReadPrivPubKey->Text = ConvertToCharpString(ConvertToCppString(private_key));
		}
		else {

			rtbReadPrivPubKey->Visible = false;
			rtbReadPrivPubKey->Clear();
		}
	}
	
	private: System::Void cbShowPublicKey_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		if (cbShowPublicKey->Checked) {
			
			cbShowPrivateKey->Checked = false;
			cbPrivateKeyEc->Checked = false;
			cbPublicKeyEc->Checked = false;

			unsigned char public_key[BUFFER];

			try
			{
				as.readPublicKeyFromFile(public_key);
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Read RSA public key failed!\n" + e->Message);
			}

			rtbReadPrivPubKey->Visible = true;
			rtbReadPrivPubKey->Text = ConvertToCharpString(ConvertToCppString(public_key));
		}
		else {

			rtbReadPrivPubKey->Visible = false;
			rtbReadPrivPubKey->Clear();
		}
	}

	private:void rsaSign() {

		lbOutput->Text = "Digital sign";
		lbOutput->ForeColor = SystemColors::HotTrack;
		lbOutAlg->Visible = true;
		rtbOutput->Enabled = false;
		cbUnlockOutput->Checked = false;
		lbOutAlg->Text = ConvertToCharpString(ConvertToCppString("RSA"));

		try
		{
			sg.setMdType(getHashType());
			sg.setRsaPrivateKey(as.getRsaPrivateKey());
			sg.setRsaPublicKey(as.getRsaPublicKey());

			std::string str = ConvertToCppString(rtbInput->Text->Trim());
			unsigned char* plaintext = (unsigned char*)malloc(BUFFER);
			if (plaintext == NULL) throw std::runtime_error(__func__);
			plaintext = ConvertToChar(str);

			sg.setInText(plaintext);
			unsigned int plain_len = strlen((char*)plaintext);
			sg.setInLen(plain_len);

			sg.rsaSign();

			unsigned char rsatext[BUFFER];
			unsigned int rsatext_len = sg.getOutLen();
			memcpy(rsatext, sg.getOutText(), rsatext_len);
			rsatext[rsatext_len] = '\0';

			std::string to_hex;
			ConvertStringToHex(rsatext, rsatext_len, to_hex);
			rtbOutput->Text = ConvertToCharpString(to_hex);

			//free(plaintext);
		}
		catch (Exception^ e)
		{
			MessageBox::Show("RSA sign failed!\n" + e->Message);
		}
	}

	private:void rsaVerify() {

		rtbOutput->Enabled = false;
		cbUnlockOutput->Checked = false;

		try
		{
			std::string str = ConvertToCppString(rtbOutput->Text->Trim());
			unsigned char from_hex[BUFFER];
			ConvertStringFromHex(str, from_hex);
			sg.setOutText(from_hex);

			sg.rsaVerify();

			if (sg.getRsaVerified() == true) {

				lbOutput->ForeColor = System::Drawing::Color::Blue;
				lbOutput->Text = "Message is VERIFIED!";
			}
			else
			{
				lbOutput->ForeColor = System::Drawing::Color::Red;
				lbOutput->Text = "Message is NOT VERIFIED!";
			}
		}
		catch (Exception^ e)
		{
			MessageBox::Show("RSA verify failed!\n" + e->Message);
		}
	}

	private:void generateEcKeys() {
		   
		try
		{
			char* public_key_path_pem = "..\\PublicKey_EC\\ec_public_key.pem";
			sg.setPublicKeyPath(public_key_path_pem);

			char* private_key_path_pem = "..\\PrivateKey_EC\\ec_private_key.pem";
			sg.setPrivateKeyPath(private_key_path_pem);

			sg.setCurve(getCurveNid());
			sg.generateECKeys();
				   
			std::string to_hex_private;
			ConvertStringToHex(sg.getECPrivateKey(), sg.getPrivateKeyLen(), to_hex_private);
			rtbPrivateKey->Text = ConvertToCharpString(to_hex_private);
				   
			std::string to_hex_public;
			ConvertStringToHex(sg.getECPublicKey(), sg.getPublicKeyLen(), to_hex_public);
			rtbPublicKey->Text = ConvertToCharpString(to_hex_public);

			lbPrivateKey->Text = "EC key";
			lbPublicKey->Text = "EC key";
		}
		catch (Exception^ e)
		{
			MessageBox::Show("EC generate keys failed!\n" + e->Message);
		}
	}

	private:void ecSign() {
		   
		lbOutput->Text = "Digital sign";
		lbOutput->ForeColor = SystemColors::HotTrack;
		lbOutAlg->Visible = true;
		rtbOutput->Enabled = false;
		cbUnlockOutput->Checked = false;
		lbOutAlg->Text = ConvertToCharpString(ConvertToCppString("EC"));

		try
		{
			std::string str = ConvertToCppString(rtbInput->Text->Trim());
			unsigned char* plaintext = (unsigned char*)malloc(BUFFER);
			if (plaintext == NULL) throw std::runtime_error(__func__);
			plaintext = ConvertToChar(str);

			sg.setInText(plaintext);
			int plain_len = strlen((char*)plaintext);
			sg.setInLen(plain_len);

			sg.ecSign();

			unsigned char ectext[BUFFER];
			unsigned int ectext_len = sg.getOutLen();
			memcpy(ectext, sg.getOutText(), ectext_len);
			ectext[ectext_len] = '\0';

			std::string to_hex;
			ConvertStringToHex(ectext, ectext_len, to_hex);
			rtbOutput->Text = ConvertToCharpString(to_hex);

			//free(plaintext);
		}
		catch (Exception^ e)
		{
			MessageBox::Show("EC sign failed!\n" + e->Message);
		}
	}

	private:void ecVerify() {
			
		rtbOutput->Enabled = false;
		cbUnlockOutput->Checked = false;

		try
		{
			std::string str = ConvertToCppString(rtbOutput->Text->Trim());
			unsigned char from_hex[BUFFER];
			ConvertStringFromHex(str, from_hex);
			sg.setOutText(from_hex);

			sg.ecVerify();

			if (true == sg.getEcVerified()) {

				lbOutput->ForeColor = System::Drawing::Color::Blue;
				lbOutput->Text = "Message is VERIFIED!";
			}
			else
			{
				lbOutput->ForeColor = System::Drawing::Color::Red;
				lbOutput->Text = "Message is NOT VERIFIED!";
			}
		}
		catch (Exception^ e)
		{
			MessageBox::Show("EC verify failed!\n" + e->Message);
		}
	}
		   
	private: System::Void btSignVerify_Click(System::Object^ sender, System::EventArgs^ e) {

		if (rbRsaSign->Checked) {

			if (ind_rsa && !ind_rsasign) {
				
				try
				{
					std::string str = ConvertToCppString(rtbInput->Text->Trim());
					if (!str.size()) {
						lbInputError->Visible = true;
						return;
					}
					else
						lbInputError->Visible = false;

					rsaSign();
				}
				catch (Exception^ e)
				{
					MessageBox::Show("RSA sign failed\n" + e->Message);
				}

				gbAsymmetric->Enabled = false;
				gbSymmetric->Enabled = false;
				gbHashMac->Enabled = false;
				gbSymmetricKey->Enabled = false;
				rbEcSign->Enabled = false;

				btSignVerify->Text = "RSA VERIFY";
				ind_rsasign = 1;
			}
			else if (ind_rsa && ind_rsasign) {

				try
				{
					rsaVerify();
				}
				catch (Exception^ e)
				{
					MessageBox::Show("RSA verify failed\n" + e->Message);
				}

				gbAsymmetric->Enabled = true;
				gbSymmetric->Enabled = true;
				gbHashMac->Enabled = true;
				gbSymmetricKey->Enabled = true;
				rbEcSign->Enabled = true;

				btSignVerify->Text = "RSA SIGN";
				ind_rsasign = 0;
			}
			else {
				lbSignKeys->Visible = true;
			}
		}
		else if (rbEcSign->Checked) {
		
			if (!ind_ecsign && !ind_sign) {
			
				lbEcKey->Visible = true;
				cbPrivateKeyEc->Enabled = true;
				cbPublicKeyEc->Enabled = true;
				pnEc->Enabled = false;

				try
				{
					generateEcKeys();
				}
				catch (Exception^ e)
				{
					MessageBox::Show("EC generate keys failed!\n" + e->Message);
				}

				btSignVerify->Text = "EC SIGN";
				ind_ecsign = 1;
				ind_sign = 1;
			}
			else if (ind_ecsign == 1) {
			
				std::string str = ConvertToCppString(rtbInput->Text->Trim());
				if (!str.size()) {
					lbInputError->Visible = true;
					return;
				}
				else
					lbInputError->Visible = false;

				try
				{
					ecSign();
				}
				catch (Exception^ e)
				{
					MessageBox::Show("EC sign failed!\n" + e->Message);
				}

				btSignVerify->Text = "EC VERIFY";
				ind_ecsign = 0;
			}
			else if (ind_ecsign == 0) {
			
				try
				{
					ecVerify();
				}
				catch (Exception^ e)
				{
					MessageBox::Show("EC verify failed!\n" + e->Message);
				}

				btSignVerify->Text = "EC SIGN";
				ind_ecsign = 1;
			}
		}
	}

	private: System::Void rbEcSign_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {

		btSignVerify->Enabled = true;
		btSignVerify->Text = "EC SIGN";
		lbOutAlg->Visible = true;
		lbOutAlg->Text = ConvertToCharpString(ConvertToCppString("EC"));

		if (!ind_once) {
			lbSignKeys->Visible = false;
		}

		if (!ind_ecsign && !ind_sign) {

			btSignVerify->Text = "GENERATE\nEC KEY";
		}
	}

	private: System::Void rbRsaSign_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {

		if (!ind_once) {

			btSignVerify->Enabled = false;
			lbSignKeys->Text = "RSA keys\nnot generated";
			lbSignKeys->Visible = true;
			lbSignKeys->ForeColor = Color::Red;
		}
		else
			btSignVerify->Enabled = true;

		if (!ind_rsasign) {
	
			btSignVerify->Text = "RSA SIGN";
			lbOutAlg->Visible = true;
			lbOutAlg->Text = ConvertToCharpString(ConvertToCppString("RSA"));
		}
		else if (ind_rsasign) {

			btSignVerify->Text = "RSA VERIFY";
			lbOutAlg->Visible = true;
			lbOutAlg->Text = ConvertToCharpString(ConvertToCppString("RSA"));
		}
	}

	private: System::Void gbSign_Enter(System::Object^ sender, System::EventArgs^ e) {
	}
	
	private: System::Void cbUnlockOutput_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {

		rtbOutput->Enabled = rtbOutput->Enabled ? false : true;
	}

	private: System::Void cbPrivateKeyEc_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		if (cbPrivateKeyEc->Checked) {

			cbShowPrivateKey->Checked = false;
			cbShowPublicKey->Checked = false;
			cbPublicKeyEc->Checked = false;

			int len = 0;
			unsigned char private_key[BUFFER];

			try
			{
				sg.readPrivateKeyFromFile(private_key, &len);
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Read EC private key failed!\n" + e->Message);
			}

			rtbReadPrivPubKey->Visible = true;
			rtbReadPrivPubKey->Text = ConvertToCharpString(ConvertToCppString(private_key));
		}
		else {

			rtbReadPrivPubKey->Visible = false;
			rtbReadPrivPubKey->Clear();
		}
	}
	
	private: System::Void checkBox2_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
		
		rtbPrivateKey->Enabled = rtbPrivateKey->Enabled ? false : true;
	}
	
	private: System::Void checkBox1_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		rtbPublicKey->Enabled = rtbPublicKey->Enabled ? false : true;
	}
	
	private: System::Void rbDes_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {

		lbKeyLentgh->Text = "Key length 8 bytes";
		lbOutAlg->Text = "DES";
	}
	
	private: System::Void rbTdes_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {

		lbKeyLentgh->Text = "Key length 16 bytes";
		lbOutAlg->Text = "TDES";
	}
	
	private: System::Void rbAes128_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {

		lbKeyLentgh->Text = "Key length 16 bytes";
		lbOutAlg->Text = "AES128";
	}
	
	private: System::Void rbAes256_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {

		lbKeyLentgh->Text = "Key length 32 bytes";
		lbOutAlg->Text = "AES256";
	}
	
	private: System::Void rbRc4_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {

		lbKeyLentgh->Text = "Key length 16 bytes";
		lbOutAlg->Text = "RC4";
	}
	
	private: System::Void gbIO_Enter(System::Object^ sender, System::EventArgs^ e) {
	}
	
	private: System::Void cbPublicKeyEc_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		if (cbPublicKeyEc->Checked) {

			cbShowPrivateKey->Checked = false;
			cbShowPublicKey->Checked = false;
			cbPrivateKeyEc->Checked = false;

			int len = 0;
			unsigned char public_key[BUFFER];

			try
			{
				sg.readPublicKeyFromFile(public_key, &len);
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Read EC public key failed!\n" + e->Message);
			}

			rtbReadPrivPubKey->Visible = true;
			rtbReadPrivPubKey->Text = ConvertToCharpString(ConvertToCppString(public_key));
		}
		else {

			rtbReadPrivPubKey->Visible = false;
			rtbReadPrivPubKey->Clear();
		}
	}
	
	private: System::Void rbRsa_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
		
		lbOutAlg->Text = "RSA";
	}
	
	private: System::Void rbMd5_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		if (rbHmac->Checked) lbOutAlg->Text = "MD5";
	}
	
	private: System::Void rbSha1_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
		
		if (rbHmac->Checked) lbOutAlg->Text = "SHA1";
	}
	
	private: System::Void rbSha256_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		if (rbHmac->Checked) lbOutAlg->Text = "SHA256";
	}
	
	private: System::Void rbSha384_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		if (rbHmac->Checked) lbOutAlg->Text = "SHA384";
	}
	
	private: System::Void rbSha512_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		if (rbHmac->Checked) lbOutAlg->Text = "SHA512";
	}
	
	private: System::Void rbCmac_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		lbOutAlg->Text = "CMAC";
	}
	
	private: System::Void rbHmac_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		lbOutAlg->Text = "HMAC";
	}
	
	private: System::Void pnEc_Paint(System::Object^ sender, System::Windows::Forms::PaintEventArgs^ e) {
	}
	
	private: System::Void btGenRootCert_Click(System::Object^ sender, System::EventArgs^ e) {

		if (ind_ca == 0)
		{
			try
			{
				ind_ca = 1;
				btGenRootCert->Text = "GENERATE\nCERT REQUEST";
				cbRootCA->Enabled = true;
				lbCAgen->Visible = true;

				cr.generateRootCA();
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Generate Root CA failed!\n" + e->Message);
			}
		}
		else if (ind_req == 0)
		{
			try
			{
				ind_req = 1;
				ind_cert = 0;
				btGenRootCert->Text = "GENERATE\nCERT FROM\nREQUEST";
				cbReadCertReq->Enabled = true;
				lbCertReq->Visible = true;

				cr.generateCertRequest();
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Generate Cert Request failed!\n" + e->Message);
			}
		}
		else if (ind_cert == 0)
		{
			try
			{
				ind_cert = 1;
				ind_req = 0;
				btGenRootCert->Text = "GENERATE\nCERT REQUEST";
				cbReadCert->Enabled = true;
				lbCertFromReq->Visible = true;
				btGenRootCert->Enabled = false;

				cr.generateCertFromRequest();
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Generate Cert from Request failed!\n" + e->Message);
			}
		}
	}

	private: System::Void cbReadCertReq_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		if (cbReadCertReq->Checked) {

			cbShowPrivateKey->Checked = false;
			cbShowPublicKey->Checked = false;
			cbPublicKeyEc->Checked = false;
			cbReadCert->Checked = false;
			cbRootCA->Checked = false;

			unsigned char cert_req[BUFFER];

			try
			{
				cr.readCertReqFromFile(cert_req);
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Read Certificate Request failed!\n" + e->Message);
			}

			rtbReadPrivPubKey->Visible = true;
			rtbReadPrivPubKey->Text = ConvertToCharpString(ConvertToCppString(cert_req));
		}
		else {

			rtbReadPrivPubKey->Visible = false;
			rtbReadPrivPubKey->Clear();
		}
	}
	
	private: System::Void cbReadCert_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	
		if (cbReadCert->Checked) {

			cbShowPrivateKey->Checked = false;
			cbShowPublicKey->Checked = false;
			cbPublicKeyEc->Checked = false;
			cbReadCertReq->Checked = false;
			cbRootCA->Checked = false;

			unsigned char cert_req[BUFFER];

			try
			{
				cr.readCertFromReqFromFile(cert_req);
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Read Certificate from Request failed!\n" + e->Message);
			}

			rtbReadPrivPubKey->Visible = true;
			rtbReadPrivPubKey->Text = ConvertToCharpString(ConvertToCppString(cert_req));
		}
		else {

			rtbReadPrivPubKey->Visible = false;
			rtbReadPrivPubKey->Clear();
		}
	}
	
	private: System::Void cbRootCA_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
		
		if (cbRootCA->Checked) {

			cbShowPrivateKey->Checked = false;
			cbShowPublicKey->Checked = false;
			cbPublicKeyEc->Checked = false;
			cbReadCertReq->Checked = false;
			cbReadCert->Checked = false;
			
			unsigned char ca_root[BUFFER];

			try
			{
				cr.readCACertFromFile(ca_root);
			}
			catch (Exception^ e)
			{
				MessageBox::Show("Read Root CA failed!\n" + e->Message);
			}

			rtbReadPrivPubKey->Visible = true;
			rtbReadPrivPubKey->Text = ConvertToCharpString(ConvertToCppString(ca_root));
		}
		else {

			rtbReadPrivPubKey->Visible = false;
			rtbReadPrivPubKey->Clear();
		}
	}
};
}