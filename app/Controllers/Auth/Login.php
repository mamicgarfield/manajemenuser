<?php

namespace App\Controllers\Auth;

use App\Controllers\BaseController;
use App\Models\UserModel;
use App\Models\LoginLogModel;

class Login extends BaseController
{
    public function index()
    {
        return view('auth/login');
    }
    public function eseclogin()
    {
        $userModel = new UserModel();
        $LoginLogModel = new LoginLogModel();
        $rules = [
            'credential' => [
                'label' => 'Email atau Username',
                'rules' => 'required|max_length[100]',
            ],
            'password' => [
                'label' => 'Password',
                'rules' => 'required',
            ],
        ];

        if (!$this->validate($rules)) {
            return $this->response->setJSON([
                'status' => false,
                'pesan' => $this->validator->getErrors()['credential'] ?? $this->validator->getErrors()['password'],
                'csrf_baru' => csrf_hash(),
            ]);
        }


        $email = $this->request->getPost('credential');
        $password = $this->request->getPost('password');
        $user = $userModel->getDataUserByEmail($email);

        if (!$user || !password_verify($password, $user['password_hash'])) {

            $LoginLogModel->save([
                'user_id'         => $user['id'] ?? null,
                'ip_address'      => $this->request->getIPAddress(),
                'user_agent'      => $this->request->getUserAgent()->getAgentString(),
                'is_success'      => false,
                'credential_used' => $email,
            ]);

            $TanggalBerhasilLoginTerakhir = $LoginLogModel->where(['ip_address' => $this->request->getIPAddress(), 'is_success' => true])->orderBy('id', 'DESC')->first()['login_at'] ?? '1970-01-01';
            $JumlahKegagalanLogin = $LoginLogModel->where(['ip_address' => $this->request->getIPAddress(), 'is_success' => false, 'login_at >' => $TanggalBerhasilLoginTerakhir])->countAllResults();

            return $this->response->setJSON([
                'status'        => false,
                'pesan'       => 'Email atau Password Salah !',
                'jumlah_kegagalan'  => $JumlahKegagalanLogin,
                'csrf_baru' => csrf_hash()
            ]);
        }

        $aktif_user = $user['is_aktif'];
        if (!$aktif_user == 1) {
            return $this->response->setJSON([
                'status' => false,
                'pesan' => 'Akun Anda tidak aktif. Silakan hubungi administrator.',
                'csrf_baru' => csrf_hash()
            ]);
        }

        $sesi = session();
        $datasesi = [
            'ses_user_id'       => $user['id'],
            'ses_email'         => $user['email'],
            'ses_username'      => $user['username'],
            'ses_nama'          => $user['nama_lengkap'],
            'ses_isLoggedIn'    => true
        ];
        $sesi->set($datasesi);

        $LoginLogModel->save([
            'user_id'    => $user['id'],
            'ip_address' => $this->request->getIPAddress(),
            'user_agent' => $this->request->getUserAgent()->getAgentString(),
            'is_success' => true,
            'credential_used' => $email,
        ]);

        return $this->response->setJSON([
            'status' => true,
            'pesan' => 'Login Berhasil!',
            'ke_route' => base_url('dashboard'),
            'csrf_baru' => csrf_hash()
        ]);
    }
    public function logout()
    {
        session()->destroy();
        return redirect()->to(base_url('login'));
    }
    public function locked()
    {
        $dataSesi = session()->get('sesi_dataTerkunci');
        session()->remove('sesi_dataTerkunci');
        $data['pesanPercobaanLogin'] = $dataSesi['pesanTerkunci'] ?? 'Terlalu banyak percobaan login.';
        $data['WaktuTerkunci'] = $dataSesi['WaktuTerkunci'] ?? null;

        return view('auth/locked', $data);
    }
    public function blocked()
    {
        return view('blocked');
    }


    public function antibruteforce() {}
}
