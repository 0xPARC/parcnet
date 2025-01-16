package pod

func Init() error {
	_, err := getOrDownloadPodWorker()
	return err
}
