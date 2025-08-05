<?= $this->extend('template/header_footer_auth'); ?>
<?= $this->section('content-auth') ?>

<div class="login-box">
    <div class="login-logo">
        <h4>Akses Dibatasi</h4>
    </div>
    <div class="card">
        <div class="card-body login-card-body text-center">
            <p class="login-box-msg">
                <i class="fas fa-lock fa-3x mb-3 text-danger"></i>
            </p>
            <p class="text-danger">
                <?= esc($pesanPercobaanLogin)
                ?>
            </p>

            <div id="hitungmundur" class="mt-3 font-weight-bold"></div>

            <hr>
            <a href="<?= base_url('/') ?>" id="kembaliKeHalamanLogin" class="btn btn-secondary btn-sm d-none">Kembali ke Halaman Login</a>
        </div>
    </div>
</div>

<script <?= csp_script_nonce() ?>>
    const WaktuTerkunci = <?= $WaktuTerkunci ?? 'null' ?>;
</script>
<script src="<?= base_url(); ?>/jsQ/locked.js"></script>
<?= $this->endSection() ?>