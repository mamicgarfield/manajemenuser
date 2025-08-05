<?php

namespace App\Filters\BruteForce;


use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use App\Models\LoginLogModel;
use App\Models\IpBlockModel;

class AntiBruteForce implements FilterInterface
{
    /**
     * @param RequestInterface|\CodeIgniter\HTTP\IncomingRequest $request           
     */

    public function before(RequestInterface $request, $arguments = null)
    {
        $logModel = new LoginLogModel();
        $IpBlockModel = new IpBlockModel();
        $ipAddress = $request->getIPAddress();
        $response = service('response');

        if ($IpBlockModel->isIpBlocked($ipAddress)) {
            session()->setFlashdata('Pesan_kirimke_halaman_locked_via_url', 'Alamat IP Anda telah diblokir secara permanen.');
            if ($request->isAJAX()) {
                return $response->setJSON(['Pesan_kirimke_ajax' => 'Anda tidak bisa login Selama lamanya :D', 'lempar_ke_url' => base_url('locked')]);
            } else {
                return redirect()->to(base_url('locked'));
            }
        }

        $terahirsukses = $logModel->where(['ip_address' => $ipAddress, 'is_success' => true])->orderBy('id', 'DESC')->first();
        $tanggalterahirsukses = $terahirsukses ? $terahirsukses['login_at'] : '1970-01-01 00:00:00';

        $dataWhere = [
            'ip_address' => $ipAddress,
            'is_success' => false,
            'login_at >' => $tanggalterahirsukses
        ];

        $getdata = $logModel->where($dataWhere)
            ->orderBy('id', 'ASC')
            ->findAll();

        $JumlahGagal = count($getdata);
        $PesanTerkunci = '';
        $KunciAkun = false;

        if ($JumlahGagal >= 15) {

            $IpBlockModel->save([
                'ip_address' => $ipAddress,
                'reason'     => 'Gagal login >= 15 kali secara beruntun.'
            ]);
            $PesanTerkunci = 'Alamat IP Anda telah diblokir secara permanen karena terlalu banyak percobaan login.';
            $KunciAkun = true;
        } elseif ($JumlahGagal >= 10) {
            $WaktuShortpadabasiske10 = strtotime($getdata[9]['login_at']);
            if (time() - $WaktuShortpadabasiske10 < 9) {
                $PesanTerkunci = 'Anda telah gagal login 10 kali. Silakan coba lagi dalam 10 menit.';
                $KunciAkun = true;
            }
        } elseif ($JumlahGagal >= 5) {
            $WaktuShortpadabasiske5 = strtotime($getdata[4]['login_at']);
            if (time() - $WaktuShortpadabasiske5 < 6) {
                $PesanTerkunci = 'Anda telah gagal login 5 kali. Silakan coba lagi dalam 1 menit.';
                $KunciAkun = true;
            }
        }

        if ($KunciAkun) {
            if ($JumlahGagal >= 10) {
                $WaktuTerkunci = strtotime($getdata[9]['login_at']) + 9;
            } else {
                $WaktuTerkunci = strtotime($getdata[4]['login_at']) + 6;
            }

            $dataKirimKeViewLocked = [
                'pesanTerkunci' => $PesanTerkunci,
                'WaktuTerkunci' => $WaktuTerkunci
            ];
            session()->set('sesi_dataTerkunci', $dataKirimKeViewLocked);

            if ($request->isAJAX()) {
                return $response->setJSON(['Pesan_kirimke_ajax' => 'terkuncidenganwaktu', 'lempar_ke_url' => base_url('locked')]);
            } else {
                return redirect()->to(base_url('locked'));
            }
        }
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null) {}
}
