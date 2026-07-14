import * as api from "@/lib/api/api";
import * as apitypes from "@/lib/api/types";
import { toast } from "@/hooks/use-toast";

const getWappalyzerData = async (
  setWappalyzer: React.Dispatch<React.SetStateAction<apitypes.wappalyzer | undefined>>,
  setTechnology: React.Dispatch<React.SetStateAction<apitypes.technologylist | undefined>>,
  setTags: React.Dispatch<React.SetStateAction<apitypes.taglist | undefined>>,
) => {
  try {
    const [wappalyzerData, technologyData, tagData] = await Promise.all([
      await api.get('wappalyzer'),
      await api.get('technology'),
      await api.get('tag'),
    ]);
    setWappalyzer(wappalyzerData);
    setTechnology(technologyData);
    setTags(tagData);
  } catch (err) {
    toast({
      title: "API Error",
      variant: "destructive",
      description: `Failed to get wappalyzer / technology / tag data: ${err}`
    });
  }
};

const getData = async (
  setLoading: React.Dispatch<React.SetStateAction<boolean>>,
  setGallery: React.Dispatch<React.SetStateAction<apitypes.galleryResult[] | undefined>>,
  setTotalPages: React.Dispatch<React.SetStateAction<number>>,
  page: number,
  limit: number,
  technologyFilter: string,
  statusFilter: string,
  schemeFilter: string,
  tagFilter: string,
  perceptionGroup: boolean,
  showFailed: boolean,
) => {
  setLoading(true);
  try {
    const s = await api.get('gallery', {
      page,
      limit,
      technologies: technologyFilter,
      status: statusFilter,
      schemes: schemeFilter,
      tags: tagFilter,
      perception: perceptionGroup ? 'true' : 'false',
      failed: showFailed ? 'true' : 'false',
    });
    setGallery(s.results);
    setTotalPages(Math.ceil(s.total_count / limit));
  } catch (err) {
    toast({
      title: "API Error",
      variant: "destructive",
      description: `Failed to get gallery: ${err}`
    });
  } finally {
    setLoading(false);
  }
};

export { getWappalyzerData, getData };
