<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Resources\CountryCollection;
use App\Http\Resources\CountryResource;
use App\Models\Country;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class CountryController extends Controller
{
    /**
     * Get all countries
     *
     * @return \App\Http\Resources\CountryCollection
     */
    public function index()
    {
        $countries = Country::orderBy('name')->get();
        
        return new CountryCollection($countries);
    }

    /**
     * Get a specific country by ID
     *
     * @param int $id
     * @return \App\Http\Resources\CountryResource|\Illuminate\Http\JsonResponse
     */
    public function show($id)
    {
        $country = Country::find($id);
        
        if (!$country) {
            return response()->json([
                'message' => 'Country not found'
            ], Response::HTTP_NOT_FOUND);
        }
        
        return new CountryResource($country);
    }

    /**
     * Get a specific country by country code
     *
     * @param string $code
     * @return \App\Http\Resources\CountryResource|\Illuminate\Http\JsonResponse
     */
    public function getByCode($code)
    {
        $country = Country::where('code', $code)->first();
        
        if (!$country) {
            return response()->json([
                'message' => 'Country not found'
            ], Response::HTTP_NOT_FOUND);
        }
        
        return new CountryResource($country);
    }

    /**
     * Search countries by name
     *
     * @param Request $request
     * @return \App\Http\Resources\CountryCollection
     */
    public function search(Request $request)
    {
        $query = $request->get('query', '');
        
        $countries = Country::where('name', 'like', "%{$query}%")
            ->orWhere('code', 'like', "%{$query}%")
            ->orderBy('name')
            ->get();
        
        return new CountryCollection($countries);
    }
}
